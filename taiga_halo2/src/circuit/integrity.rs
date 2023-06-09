use std::ops::Neg;

use crate::circuit::gadgets::{
    add::{AddChip, AddInstructions},
    assign_free_advice, assign_free_constant,
};
use crate::circuit::{
    hash_to_curve::{hash_to_curve_circuit, HashToCurveConfig},
    note_circuit::{note_commitment_gadget, NoteCommitmentChip},
    vp_circuit::{InputNoteVariables, NoteVariables, OutputNoteVariables},
};
use crate::constant::{
    NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentFixedBasesFull,
    NoteCommitmentHashDomain, NullifierK, POSEIDON_TO_CURVE_INPUT_LEN,
};
use crate::note::Note;
use crate::utils::poseidon_to_curve;
use halo2_gadgets::{
    ecc::{
        chip::EccChip, FixedPoint, FixedPointBaseField, NonIdentityPoint, Point, ScalarFixed,
        ScalarVar,
    },
    poseidon::{
        primitives as poseidon, primitives::ConstantLength, Hash as PoseidonHash,
        Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
    },
    sinsemilla::chip::SinsemillaChip,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, Error, Instance},
};
use pasta_curves::group::Curve;
use pasta_curves::pallas;

// cm is a point
#[allow(clippy::too_many_arguments)]
pub fn nullifier_circuit(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_chip: PoseidonChip<pallas::Base, 3, 2>,
    add_chip: AddChip<pallas::Base>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: AssignedCell<pallas::Base, pallas::Base>,
    cm: &Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    let poseidon_message = [nk, rho];
    let poseidon_hasher =
        PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            poseidon_chip,
            layouter.namespace(|| "Poseidon init"),
        )?;
    let hash_nk_rho = poseidon_hasher.hash(
        layouter.namespace(|| "Poseidon_hash(nk, rho)"),
        poseidon_message,
    )?;

    let hash_nk_rho_add_psi = add_chip.add(
        layouter.namespace(|| "scalar = poseidon_hash(nk, rho) + psi"),
        &hash_nk_rho,
        &psi,
    )?;

    // TODO: generate a new generator for nullifier_k
    let nullifier_k = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
    let hash_nk_rho_add_psi_mul_k = nullifier_k.mul(
        layouter.namespace(|| "hash_nk_rho_add_psi * nullifier_k"),
        hash_nk_rho_add_psi,
    )?;

    cm.add(layouter.namespace(|| "nf"), &hash_nk_rho_add_psi_mul_k)
        .map(|res| res.extract_p().inner().clone())
}

// Check input note integrity and return the input note variables and the nullifier
#[allow(clippy::too_many_arguments)]
pub fn check_input_note(
    mut layouter: impl Layouter<pallas::Base>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    sinsemilla_chip: SinsemillaChip<
        NoteCommitmentHashDomain,
        NoteCommitmentDomain,
        NoteCommitmentFixedBases,
    >,
    note_commit_chip: NoteCommitmentChip,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    // poseidon_chip: PoseidonChip<pallas::Base, 3, 2>,
    add_chip: AddChip<pallas::Base>,
    input_note: Note,
    nf_row_idx: usize,
) -> Result<InputNoteVariables, Error> {
    // Check input note user integrity: address = Com_r(Com_r(nk, zero), app_data_dynamic)
    let (address, nk, app_data_dynamic) = {
        // Witness nk
        let nk = input_note.get_nk().unwrap();
        let nk_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(nk.inner()),
        )?;

        let zero_constant = assign_free_constant(
            layouter.namespace(|| "constant zero"),
            advices[0],
            pallas::Base::zero(),
        )?;

        // nk_com = Com_r(nk, zero)
        let nk_com = {
            let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [nk_var.clone(), zero_constant];
            poseidon_hasher.hash(layouter.namespace(|| "nk_com"), poseidon_message)?
        };

        // Witness app_data_dynamic
        let app_data_dynamic = assign_free_advice(
            layouter.namespace(|| "witness app_data_dynamic"),
            advices[0],
            Value::known(input_note.app_data_dynamic),
        )?;

        // address = Com_r(app_data_dynamic, nk_com)
        let address = {
            let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [app_data_dynamic.clone(), nk_com];
            poseidon_hasher.hash(layouter.namespace(|| "input address"), poseidon_message)?
        };

        (address, nk_var, app_data_dynamic)
    };

    // Witness app_vk
    let app_vk = assign_free_advice(
        layouter.namespace(|| "witness app_vk"),
        advices[0],
        Value::known(input_note.get_app_vk()),
    )?;

    // Witness app_data_static
    let app_data_static = assign_free_advice(
        layouter.namespace(|| "witness app_data_static"),
        advices[0],
        Value::known(input_note.get_app_data_static()),
    )?;

    // Witness value(u64)
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(pallas::Base::from(input_note.value)),
    )?;

    // Witness rho
    let rho = assign_free_advice(
        layouter.namespace(|| "witness rho"),
        advices[0],
        Value::known(input_note.rho.inner()),
    )?;

    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_input"),
        advices[0],
        Value::known(input_note.psi),
    )?;

    // Witness rcm
    let rcm = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "rcm"),
        Value::known(input_note.rcm),
    )?;

    // Witness is_merkle_checked
    let is_merkle_checked = assign_free_advice(
        layouter.namespace(|| "witness is_merkle_checked"),
        advices[0],
        Value::known(pallas::Base::from(input_note.is_merkle_checked)),
    )?;

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip.clone(),
        note_commit_chip,
        address.clone(),
        app_vk.clone(),
        app_data_static.clone(),
        rho.clone(),
        psi.clone(),
        value.clone(),
        rcm,
        is_merkle_checked.clone(),
    )?;

    // Generate nullifier
    let poseidon_chip = PoseidonChip::construct(poseidon_config);
    let nf = nullifier_circuit(
        layouter.namespace(|| "Generate nullifier"),
        poseidon_chip,
        add_chip,
        ecc_chip,
        nk,
        rho,
        psi,
        &cm,
    )?;

    // Public nullifier
    layouter.constrain_instance(nf.cell(), instances, nf_row_idx)?;

    let cm_x = cm.extract_p().inner().clone();

    let note_variables = NoteVariables {
        address,
        app_vk,
        value,
        app_data_static,
        is_merkle_checked,
        app_data_dynamic,
    };

    Ok(InputNoteVariables {
        note_variables,
        nf,
        cm_x,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn check_output_note(
    mut layouter: impl Layouter<pallas::Base>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    sinsemilla_chip: SinsemillaChip<
        NoteCommitmentHashDomain,
        NoteCommitmentDomain,
        NoteCommitmentFixedBases,
    >,
    note_commit_chip: NoteCommitmentChip,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    // poseidon_chip: PoseidonChip<pallas::Base, 3, 2>,
    output_note: Note,
    old_nf: AssignedCell<pallas::Base, pallas::Base>,
    cm_row_idx: usize,
) -> Result<OutputNoteVariables, Error> {
    // Check output note user integrity: address = Com_r(app_data_dynamic, nk_com)
    let (address, app_data_dynamic) = {
        // Witness nk_com
        let nk_com = assign_free_advice(
            layouter.namespace(|| "witness nk_com"),
            advices[0],
            Value::known(output_note.nk_com.get_nk_com()),
        )?;

        // Witness app_data_dynamic
        let app_data_dynamic = assign_free_advice(
            layouter.namespace(|| "witness app_data_dynamic"),
            advices[0],
            Value::known(output_note.app_data_dynamic),
        )?;

        let poseidon_chip = PoseidonChip::construct(poseidon_config);
        let poseidon_hasher =
            PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                poseidon_chip,
                layouter.namespace(|| "Poseidon init"),
            )?;
        let poseidon_message = [app_data_dynamic.clone(), nk_com];
        (
            poseidon_hasher.hash(layouter.namespace(|| "output address"), poseidon_message)?,
            app_data_dynamic,
        )
    };

    // Witness app_vk
    let app_vk = assign_free_advice(
        layouter.namespace(|| "witness app_vk"),
        advices[0],
        Value::known(output_note.get_app_vk()),
    )?;

    // Witness app_data_static
    let app_data_static = assign_free_advice(
        layouter.namespace(|| "witness app_data_static"),
        advices[0],
        Value::known(output_note.get_app_data_static()),
    )?;

    // Witness value(u64)
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(pallas::Base::from(output_note.value)),
    )?;

    // Witness rcm
    let rcm = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "rcm"),
        Value::known(output_note.rcm),
    )?;

    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_output"),
        advices[0],
        Value::known(output_note.psi),
    )?;

    // Witness is_merkle_checked
    let is_merkle_checked = assign_free_advice(
        layouter.namespace(|| "witness is_merkle_checked"),
        advices[0],
        Value::known(pallas::Base::from(output_note.is_merkle_checked)),
    )?;

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip,
        note_commit_chip,
        address.clone(),
        app_vk.clone(),
        app_data_static.clone(),
        old_nf,
        psi,
        value.clone(),
        rcm,
        is_merkle_checked.clone(),
    )?;

    // Public cm
    let cm_x = cm.extract_p().inner().clone();
    layouter.constrain_instance(cm_x.cell(), instances, cm_row_idx)?;

    let note_variables = NoteVariables {
        address,
        app_vk,
        app_data_static,
        value,
        is_merkle_checked,
        app_data_dynamic,
    };

    Ok(OutputNoteVariables {
        note_variables,
        cm_x,
    })
}

pub fn derive_value_base(
    mut layouter: impl Layouter<pallas::Base>,
    hash_to_curve_config: HashToCurveConfig,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    app_vk: AssignedCell<pallas::Base, pallas::Base>,
    app_data_static: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<NonIdentityPoint<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
    let point = hash_to_curve_circuit(
        layouter.namespace(|| "hash to curve"),
        hash_to_curve_config,
        ecc_chip.clone(),
        &[app_vk.clone(), app_data_static.clone()],
    )?;

    // Assign a new `NonIdentityPoint` and constran equal to hash_to_curve point since `Point` doesn't have mul operation
    // IndentityPoint is an invalid value base and it returns an error.
    let non_identity_point = app_vk
        .value()
        .zip(app_data_static.value())
        .map(|(&vk, &data)| {
            poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&[vk, data]).to_affine()
        });
    let non_identity_point_var = NonIdentityPoint::new(
        ecc_chip,
        layouter.namespace(|| "non-identity value base"),
        non_identity_point,
    )?;
    point.constrain_equal(
        layouter.namespace(|| "non-identity value base"),
        &non_identity_point_var,
    )?;
    Ok(non_identity_point_var)
}

#[allow(clippy::too_many_arguments)]
pub fn compute_value_commitment(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    hash_to_curve_config: HashToCurveConfig,
    app_address_input: AssignedCell<pallas::Base, pallas::Base>,
    data_input: AssignedCell<pallas::Base, pallas::Base>,
    v_input: AssignedCell<pallas::Base, pallas::Base>,
    app_address_output: AssignedCell<pallas::Base, pallas::Base>,
    data_output: AssignedCell<pallas::Base, pallas::Base>,
    v_output: AssignedCell<pallas::Base, pallas::Base>,
    rcv: pallas::Scalar,
) -> Result<Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
    // input value point
    let value_base_input = derive_value_base(
        layouter.namespace(|| "derive input value base"),
        hash_to_curve_config.clone(),
        ecc_chip.clone(),
        app_address_input,
        data_input,
    )?;
    let v_input_scalar = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &v_input,
    )?;
    let (value_point_input, _) =
        value_base_input.mul(layouter.namespace(|| "input value point"), v_input_scalar)?;

    // output value point
    let value_base_output = derive_value_base(
        layouter.namespace(|| "derive output value base"),
        hash_to_curve_config,
        ecc_chip.clone(),
        app_address_output,
        data_output,
    )?;
    let v_output_scalar = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &v_output,
    )?;
    let (value_point_output, _) =
        value_base_output.mul(layouter.namespace(|| "output value point"), v_output_scalar)?;

    // Get and constrain the negative output value point
    let neg_v_point_output = Point::new(
        ecc_chip.clone(),
        layouter.namespace(|| "negative output value point"),
        value_point_output.inner().point().neg(),
    )?;

    let zero_point = value_point_output.add(
        layouter.namespace(|| "value_point + neg_value_point"),
        &neg_v_point_output,
    )?;
    layouter.assign_region(
        || "constrain zero point",
        |mut region| {
            // Constrain x-coordinates
            region.constrain_constant(zero_point.inner().x().cell(), pallas::Base::zero())?;
            // Constrain y-coordinates
            region.constrain_constant(zero_point.inner().y().cell(), pallas::Base::zero())
        },
    )?;

    let commitment_v = value_point_input.add(
        layouter.namespace(|| "v_pioint_input - v_point_output"),
        &neg_v_point_output,
    )?;

    // blind point
    let blind_scalar = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "blind scalar"),
        Value::known(rcv),
    )?;

    let blind_base = FixedPoint::from_inner(ecc_chip, NoteCommitmentFixedBasesFull);
    let (blind, _) = blind_base.mul(
        layouter.namespace(|| "blind_scalar * blind_base"),
        &blind_scalar,
    )?;

    commitment_v.add(layouter.namespace(|| "net value commitment"), &blind)
}

#[test]
fn test_halo2_nullifier_circuit() {
    use crate::circuit::gadgets::add::AddConfig;
    use crate::circuit::gadgets::assign_free_advice;
    use crate::constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain,
    };
    use crate::note::NoteCommitment;
    use crate::nullifier::{Nullifier, NullifierDerivingKey};
    use halo2_gadgets::{
        ecc::chip::EccConfig,
        poseidon::{
            primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
        },
        sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use rand::rngs::OsRng;

    #[derive(Default)]
    struct MyCircuit {
        nk: NullifierDerivingKey,
        rho: pallas::Base,
        psi: pallas::Base,
        cm: NoteCommitment,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        #[allow(clippy::type_complexity)]
        type Config = (
            [Column<Advice>; 10],
            PoseidonConfig<pallas::Base, 3, 2>,
            AddConfig,
            EccConfig<NoteCommitmentFixedBases>,
            // add SinsemillaConfig to load look table, just for test
            SinsemillaConfig<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];

            for advice in advices.iter() {
                meta.enable_equality(*advice);
            }

            let lagrange_coeffs = [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ];

            let table_idx = meta.lookup_table_column();
            let lookup = (
                table_idx,
                meta.lookup_table_column(),
                meta.lookup_table_column(),
            );

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
            let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
                meta,
                advices[6..9].try_into().unwrap(),
                advices[5],
                lagrange_coeffs[2..5].try_into().unwrap(),
                lagrange_coeffs[5..8].try_into().unwrap(),
            );

            let add_config = AddChip::configure(meta, advices[0..2].try_into().unwrap());

            let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
                meta,
                advices,
                lagrange_coeffs,
                range_check,
            );
            let sinsemilla_config = SinsemillaChip::<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[2],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );
            (
                advices,
                poseidon_config,
                add_config,
                ecc_config,
                sinsemilla_config,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, poseidon_config, add_config, ecc_config, sinsemilla_config) = config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let ecc_chip = EccChip::construct(ecc_config);
            let add_chip = AddChip::<pallas::Base>::construct(add_config, ());
            SinsemillaChip::<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >::load(sinsemilla_config, &mut layouter)?;

            // Witness nk
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                advices[0],
                Value::known(self.nk.inner()),
            )?;

            // Witness rho
            let rho = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                advices[0],
                Value::known(self.rho),
            )?;

            // Witness psi
            let psi = assign_free_advice(
                layouter.namespace(|| "witness psi"),
                advices[0],
                Value::known(self.psi),
            )?;

            // Witness cm
            let cm = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness cm"),
                Value::known(self.cm.inner().to_affine()),
            )?;

            let nf = nullifier_circuit(
                layouter.namespace(|| "nullifier"),
                poseidon_chip,
                add_chip,
                ecc_chip,
                nk,
                rho,
                psi,
                &cm,
            )?;

            let expect_nf = {
                let nf = Nullifier::derive_native(&self.nk, &self.rho, &self.psi, &self.cm).inner();
                assign_free_advice(
                    layouter.namespace(|| "witness nf"),
                    advices[0],
                    Value::known(nf),
                )?
            };

            layouter.assign_region(
                || "constrain result",
                |mut region| region.constrain_equal(nf.cell(), expect_nf.cell()),
            )
        }
    }

    let mut rng = OsRng;
    let circuit = MyCircuit {
        nk: NullifierDerivingKey::rand(&mut rng),
        rho: pallas::Base::random(&mut rng),
        psi: pallas::Base::random(&mut rng),
        cm: NoteCommitment::default(),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
