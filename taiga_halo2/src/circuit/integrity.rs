use crate::circuit::{
    gadgets::{assign_free_advice, assign_free_constant, poseidon_hash::poseidon_hash_gadget},
    hash_to_curve::{hash_to_curve_circuit, HashToCurveConfig},
    vp_circuit::{InputNoteVariables, NoteVariables, OutputNoteVariables},
};
use crate::constant::{TaigaFixedBases, TaigaFixedBasesFull, POSEIDON_TO_CURVE_INPUT_LEN};
use crate::note::Note;
use crate::utils::poseidon_to_curve;
use halo2_gadgets::{
    ecc::{chip::EccChip, FixedPoint, NonIdentityPoint, Point, ScalarFixed, ScalarVar},
    poseidon::Pow5Config as PoseidonConfig,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, Error, Instance},
};
use pasta_curves::group::Curve;
use pasta_curves::pallas;
use std::ops::Neg;

#[allow(clippy::too_many_arguments)]
pub fn note_commitment_circuit(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    app_vp: AssignedCell<pallas::Base, pallas::Base>,
    app_data_static: AssignedCell<pallas::Base, pallas::Base>,
    app_data_dynamic: AssignedCell<pallas::Base, pallas::Base>,
    nk_com: AssignedCell<pallas::Base, pallas::Base>,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: AssignedCell<pallas::Base, pallas::Base>,
    value: AssignedCell<pallas::Base, pallas::Base>,
    is_merkle_checked: AssignedCell<pallas::Base, pallas::Base>,
    rcm: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    // TODO: compose the value and is_merkle_checked to one field in order to save one poseidon absorb
    let poseidon_message = [
        app_vp,
        app_data_static,
        app_data_dynamic,
        nk_com,
        rho,
        psi,
        is_merkle_checked,
        value,
        rcm,
    ];
    poseidon_hash_gadget(
        poseidon_config,
        layouter.namespace(|| "note commitment"),
        poseidon_message,
    )
}

// cm is a field element
#[allow(clippy::too_many_arguments)]
pub fn nullifier_circuit(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: AssignedCell<pallas::Base, pallas::Base>,
    cm: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    let poseidon_message = [nk, rho, psi, cm];
    poseidon_hash_gadget(
        poseidon_config,
        layouter.namespace(|| "derive nullifier"),
        poseidon_message,
    )
}

// Check input note integrity and return the input note variables and the nullifier
#[allow(clippy::too_many_arguments)]
pub fn check_input_note(
    mut layouter: impl Layouter<pallas::Base>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    input_note: Note,
    nf_row_idx: usize,
) -> Result<InputNoteVariables, Error> {
    // Witness nk
    let nk = input_note.get_nk().unwrap();
    let nk_var = assign_free_advice(
        layouter.namespace(|| "witness nk"),
        advices[0],
        Value::known(nk),
    )?;

    let zero_constant = assign_free_constant(
        layouter.namespace(|| "constant zero"),
        advices[0],
        pallas::Base::zero(),
    )?;

    // nk_com = Com_r(nk, zero)
    let nk_com = poseidon_hash_gadget(
        poseidon_config.clone(),
        layouter.namespace(|| "nk_com encoding"),
        [nk_var.clone(), zero_constant],
    )?;

    // Witness app_data_dynamic
    let app_data_dynamic = assign_free_advice(
        layouter.namespace(|| "witness app_data_dynamic"),
        advices[0],
        Value::known(input_note.app_data_dynamic),
    )?;

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
        Value::known(input_note.get_psi()),
    )?;

    // Witness rcm
    let rcm = assign_free_advice(
        layouter.namespace(|| "witness rcm"),
        advices[0],
        Value::known(input_note.get_rcm()),
    )?;

    // Witness is_merkle_checked
    let is_merkle_checked = assign_free_advice(
        layouter.namespace(|| "witness is_merkle_checked"),
        advices[0],
        Value::known(pallas::Base::from(input_note.is_merkle_checked)),
    )?;

    // Check note commitment
    let cm = note_commitment_circuit(
        layouter.namespace(|| "note commitment"),
        poseidon_config.clone(),
        app_vk.clone(),
        app_data_static.clone(),
        app_data_dynamic.clone(),
        nk_com.clone(),
        rho.clone(),
        psi.clone(),
        value.clone(),
        is_merkle_checked.clone(),
        rcm.clone(),
    )?;

    // Generate nullifier
    let nf = nullifier_circuit(
        layouter.namespace(|| "Generate nullifier"),
        poseidon_config,
        nk_var,
        rho.clone(),
        psi.clone(),
        cm.clone(),
    )?;

    // Public nullifier
    layouter.constrain_instance(nf.cell(), instances, nf_row_idx)?;

    let note_variables = NoteVariables {
        app_vk,
        value,
        app_data_static,
        is_merkle_checked,
        app_data_dynamic,
        rho,
        nk_com,
        psi,
        rcm,
    };

    Ok(InputNoteVariables {
        note_variables,
        nf,
        cm,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn check_output_note(
    mut layouter: impl Layouter<pallas::Base>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    // poseidon_chip: PoseidonChip<pallas::Base, 3, 2>,
    output_note: Note,
    old_nf: AssignedCell<pallas::Base, pallas::Base>,
    cm_row_idx: usize,
) -> Result<OutputNoteVariables, Error> {
    // Witness nk_com
    let nk_com = assign_free_advice(
        layouter.namespace(|| "witness nk_com"),
        advices[0],
        Value::known(output_note.get_nk_commitment()),
    )?;

    // Witness app_data_dynamic
    let app_data_dynamic = assign_free_advice(
        layouter.namespace(|| "witness app_data_dynamic"),
        advices[0],
        Value::known(output_note.app_data_dynamic),
    )?;

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
    let rcm = assign_free_advice(
        layouter.namespace(|| "witness rcm"),
        advices[0],
        Value::known(output_note.get_rcm()),
    )?;

    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_output"),
        advices[0],
        Value::known(output_note.get_psi()),
    )?;

    // Witness is_merkle_checked
    let is_merkle_checked = assign_free_advice(
        layouter.namespace(|| "witness is_merkle_checked"),
        advices[0],
        Value::known(pallas::Base::from(output_note.is_merkle_checked)),
    )?;

    // Check note commitment
    let cm = note_commitment_circuit(
        layouter.namespace(|| "note commitment"),
        poseidon_config.clone(),
        app_vk.clone(),
        app_data_static.clone(),
        app_data_dynamic.clone(),
        nk_com.clone(),
        old_nf.clone(),
        psi.clone(),
        value.clone(),
        is_merkle_checked.clone(),
        rcm.clone(),
    )?;

    // Public cm
    layouter.constrain_instance(cm.cell(), instances, cm_row_idx)?;

    let note_variables = NoteVariables {
        app_vk,
        app_data_static,
        value,
        is_merkle_checked,
        app_data_dynamic,
        rho: old_nf,
        nk_com,
        psi,
        rcm,
    };

    Ok(OutputNoteVariables { note_variables, cm })
}

pub fn derive_note_type(
    mut layouter: impl Layouter<pallas::Base>,
    hash_to_curve_config: HashToCurveConfig,
    ecc_chip: EccChip<TaigaFixedBases>,
    app_vk: AssignedCell<pallas::Base, pallas::Base>,
    app_data_static: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<NonIdentityPoint<pallas::Affine, EccChip<TaigaFixedBases>>, Error> {
    let point = hash_to_curve_circuit(
        layouter.namespace(|| "hash to curve"),
        hash_to_curve_config,
        ecc_chip.clone(),
        &[app_vk.clone(), app_data_static.clone()],
    )?;

    // Assign a new `NonIdentityPoint` and constran equal to hash_to_curve point since `Point` doesn't have mul operation
    // IndentityPoint is an invalid note type and it returns an error.
    let non_identity_point = app_vk
        .value()
        .zip(app_data_static.value())
        .map(|(&vk, &data)| {
            poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&[vk, data]).to_affine()
        });
    let non_identity_point_var = NonIdentityPoint::new(
        ecc_chip,
        layouter.namespace(|| "non-identity note type"),
        non_identity_point,
    )?;
    point.constrain_equal(
        layouter.namespace(|| "non-identity note type"),
        &non_identity_point_var,
    )?;
    Ok(non_identity_point_var)
}

#[allow(clippy::too_many_arguments)]
pub fn compute_value_commitment(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip<TaigaFixedBases>,
    hash_to_curve_config: HashToCurveConfig,
    app_address_input: AssignedCell<pallas::Base, pallas::Base>,
    data_input: AssignedCell<pallas::Base, pallas::Base>,
    v_input: AssignedCell<pallas::Base, pallas::Base>,
    app_address_output: AssignedCell<pallas::Base, pallas::Base>,
    data_output: AssignedCell<pallas::Base, pallas::Base>,
    v_output: AssignedCell<pallas::Base, pallas::Base>,
    rcv: pallas::Scalar,
) -> Result<Point<pallas::Affine, EccChip<TaigaFixedBases>>, Error> {
    // input value point
    let note_type_input = derive_note_type(
        layouter.namespace(|| "derive input note type"),
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
        note_type_input.mul(layouter.namespace(|| "input value point"), v_input_scalar)?;

    // output value point
    let note_type_output = derive_note_type(
        layouter.namespace(|| "derive output note type"),
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
        note_type_output.mul(layouter.namespace(|| "output value point"), v_output_scalar)?;

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

    let blind_base = FixedPoint::from_inner(ecc_chip, TaigaFixedBasesFull::NoteCommitmentR);
    let (blind, _) = blind_base.mul(
        layouter.namespace(|| "blind_scalar * blind_base"),
        &blind_scalar,
    )?;

    commitment_v.add(layouter.namespace(|| "net value commitment"), &blind)
}

#[test]
fn test_halo2_nullifier_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use crate::note::NoteCommitment;
    use crate::nullifier::{Nullifier, NullifierKeyContainer};
    use halo2_gadgets::poseidon::{
        primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
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
        nk: NullifierKeyContainer,
        rho: pallas::Base,
        psi: pallas::Base,
        cm: NoteCommitment,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        #[allow(clippy::type_complexity)]
        type Config = ([Column<Advice>; 10], PoseidonConfig<pallas::Base, 3, 2>);
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

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
                meta,
                advices[6..9].try_into().unwrap(),
                advices[5],
                lagrange_coeffs[2..5].try_into().unwrap(),
                lagrange_coeffs[5..8].try_into().unwrap(),
            );
            (advices, poseidon_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, poseidon_config) = config;
            // Witness nk
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                advices[0],
                Value::known(self.nk.get_nk().unwrap()),
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
            let cm = assign_free_advice(
                layouter.namespace(|| "witness cm"),
                advices[0],
                Value::known(self.cm.inner()),
            )?;

            let nf = nullifier_circuit(
                layouter.namespace(|| "nullifier"),
                poseidon_config,
                nk,
                rho,
                psi,
                cm,
            )?;

            let expect_nf = {
                let nf = Nullifier::derive(&self.nk, &self.rho, &self.psi, &self.cm)
                    .unwrap()
                    .inner();
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
        nk: NullifierKeyContainer::random_key(&mut rng),
        rho: pallas::Base::random(&mut rng),
        psi: pallas::Base::random(&mut rng),
        cm: NoteCommitment::default(),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
