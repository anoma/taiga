use std::ops::Neg;

use crate::circuit::gadgets::{assign_free_advice, AddChip, AddInstructions};
use crate::circuit::note_circuit::{note_commitment_gadget, NoteCommitmentChip};
use crate::constant::{
    NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentFixedBasesFull,
    NoteCommitmentHashDomain, NullifierK,
};
use crate::note::Note;
use ff::PrimeField;
use group::Curve;
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

// Return variables in the spend note
#[derive(Debug)]
pub struct SpendNoteVar {
    pub user_address: AssignedCell<pallas::Base, pallas::Base>,
    pub app_vp: AssignedCell<pallas::Base, pallas::Base>,
    pub app_data: AssignedCell<pallas::Base, pallas::Base>,
    pub value: AssignedCell<pallas::Base, pallas::Base>,
    pub nf: AssignedCell<pallas::Base, pallas::Base>,
    pub cm: Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
    pub is_normal: AssignedCell<pallas::Base, pallas::Base>,
}

#[allow(clippy::too_many_arguments)]
pub fn check_spend_note(
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
    spend_note: Note,
    nf_row_idx: usize,
) -> Result<SpendNoteVar, Error> {
    // Check spend note user integrity: user_address = Com_r(Com_r(send_vp, nk), recv_vp_hash)
    let (user_address, nk) = {
        // Witness send_data
        let send_data = spend_note.application.get_user_send_data().unwrap();
        let send_vp_var = assign_free_advice(
            layouter.namespace(|| "witness user send data"),
            advices[0],
            Value::known(send_data),
        )?;

        // Witness nk
        let nk = spend_note.application.get_nk().unwrap();
        let nk_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(nk.inner()),
        )?;

        // send_com = Com_r(send_data, nk)
        let send_com = {
            let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [send_vp_var, nk_var.clone()];
            poseidon_hasher.hash(layouter.namespace(|| "send_com"), poseidon_message)?
        };

        // Witness recv_data
        let recv_data = assign_free_advice(
            layouter.namespace(|| "witness user recv data"),
            advices[0],
            Value::known(spend_note.application.get_user_recv_data()),
        )?;

        // user_address = Com_r(send_com, recv_vp_data)
        let user_address = {
            let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [send_com, recv_data];
            poseidon_hasher.hash(layouter.namespace(|| "user_address"), poseidon_message)?
        };

        (user_address, nk_var)
    };

    // Witness app_vp
    let app_vp = assign_free_advice(
        layouter.namespace(|| "witness app_vp"),
        advices[0],
        Value::known(spend_note.application.get_vp()),
    )?;

    // Witness app_data
    let app_data = assign_free_advice(
        layouter.namespace(|| "witness app_vp_data"),
        advices[0],
        Value::known(spend_note.application.vp_data),
    )?;

    // Witness value(u64)
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(pallas::Base::from(spend_note.value)),
    )?;

    // Witness rho
    let rho = assign_free_advice(
        layouter.namespace(|| "witness rho"),
        advices[0],
        Value::known(spend_note.rho.inner()),
    )?;

    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_spend"),
        advices[0],
        Value::known(spend_note.psi),
    )?;

    // Witness rcm
    let rcm = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "rcm"),
        Value::known(spend_note.rcm),
    )?;

    // Witness is_normal
    let is_normal = assign_free_advice(
        layouter.namespace(|| "witness is_normal"),
        advices[0],
        Value::known(pallas::Base::from(spend_note.is_normal)),
    )?;

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip.clone(),
        note_commit_chip,
        user_address.clone(),
        app_vp.clone(),
        app_data.clone(),
        rho.clone(),
        psi.clone(),
        value.clone(),
        rcm,
        is_normal.clone(),
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

    Ok(SpendNoteVar {
        user_address,
        app_vp,
        value,
        app_data,
        nf,
        cm,
        is_normal,
    })
}

// Return variables in the spend note
#[derive(Debug)]
pub struct OutputNoteVar {
    pub user_address: AssignedCell<pallas::Base, pallas::Base>,
    pub app_vp: AssignedCell<pallas::Base, pallas::Base>,
    pub app_data: AssignedCell<pallas::Base, pallas::Base>,
    pub value: AssignedCell<pallas::Base, pallas::Base>,
    pub cm: Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
    pub is_normal: AssignedCell<pallas::Base, pallas::Base>,
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
) -> Result<OutputNoteVar, Error> {
    // Check output note user integrity: user_address = Com_r(send_com, recv_vp_hash)
    let user_address = {
        let send_com = assign_free_advice(
            layouter.namespace(|| "witness output send_com"),
            advices[0],
            Value::known(output_note.application.get_user_send_closed()),
        )?;
        // Witness recv data
        let recv_data = assign_free_advice(
            layouter.namespace(|| "witness user recv data"),
            advices[0],
            Value::known(output_note.application.get_user_recv_data()),
        )?;

        let poseidon_chip = PoseidonChip::construct(poseidon_config);
        let poseidon_hasher =
            PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                poseidon_chip,
                layouter.namespace(|| "Poseidon init"),
            )?;
        let poseidon_message = [send_com, recv_data];
        poseidon_hasher.hash(layouter.namespace(|| "user_address"), poseidon_message)?
    };

    // Witness app_vp
    let app_vp = assign_free_advice(
        layouter.namespace(|| "witness app_vp"),
        advices[0],
        Value::known(output_note.application.get_vp()),
    )?;

    // Witness app_data
    let app_data = assign_free_advice(
        layouter.namespace(|| "witness app_data"),
        advices[0],
        Value::known(output_note.application.vp_data),
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

    // Witness is_normal
    let is_normal = assign_free_advice(
        layouter.namespace(|| "witness is_normal"),
        advices[0],
        Value::known(pallas::Base::from(output_note.is_normal)),
    )?;

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip,
        note_commit_chip,
        user_address.clone(),
        app_vp.clone(),
        app_data.clone(),
        old_nf,
        psi,
        value.clone(),
        rcm,
        is_normal.clone(),
    )?;

    // Public cm
    let cm_x = cm.extract_p().inner().clone();
    layouter.constrain_instance(cm_x.cell(), instances, cm_row_idx)?;

    Ok(OutputNoteVar {
        user_address,
        app_vp,
        app_data,
        value,
        cm,
        is_normal,
    })
}

// TODO: add hash_to_curve circuit to derivate the value base
pub fn derivate_value_base(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    is_normal: AssignedCell<pallas::Base, pallas::Base>,
    app_vp: AssignedCell<pallas::Base, pallas::Base>,
    app_data: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<NonIdentityPoint<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
    let out_of_circuit_value_base = {
        use halo2_proofs::arithmetic::CurveExt;
        let hash = pallas::Point::hash_to_curve("taiga:test");
        let mut bytes: Vec<u8> = vec![];
        is_normal.value().map(|v| bytes.push(v.to_repr()[0]));
        app_vp.value().map(|x| {
            bytes.extend_from_slice(&x.to_repr());
        });
        app_data.value().map(|x| {
            bytes.extend_from_slice(&x.to_repr());
        });
        hash(&bytes)
    };
    NonIdentityPoint::new(
        ecc_chip,
        layouter.namespace(|| "derivate value base"),
        Value::known(out_of_circuit_value_base.to_affine()),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compute_net_value_commitment(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    is_normal_spend: AssignedCell<pallas::Base, pallas::Base>,
    app_address_spend: AssignedCell<pallas::Base, pallas::Base>,
    data_spend: AssignedCell<pallas::Base, pallas::Base>,
    v_spend: AssignedCell<pallas::Base, pallas::Base>,
    is_normal_output: AssignedCell<pallas::Base, pallas::Base>,
    app_address_output: AssignedCell<pallas::Base, pallas::Base>,
    data_output: AssignedCell<pallas::Base, pallas::Base>,
    v_output: AssignedCell<pallas::Base, pallas::Base>,
    rcv: pallas::Scalar,
) -> Result<Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
    // spend value point
    let value_base_spend = derivate_value_base(
        layouter.namespace(|| "derivate spend value base"),
        ecc_chip.clone(),
        is_normal_spend,
        app_address_spend,
        data_spend,
    )?;
    let v_spend_scalar = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &v_spend,
    )?;
    let (value_point_spend, _) =
        value_base_spend.mul(layouter.namespace(|| "spend value point"), v_spend_scalar)?;

    // output value point
    let value_base_output = derivate_value_base(
        layouter.namespace(|| "derivate output value base"),
        ecc_chip.clone(),
        is_normal_output,
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

    let commitment_v = value_point_spend.add(
        layouter.namespace(|| "v_pioint_spend - v_point_output"),
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
    use crate::circuit::gadgets::assign_free_advice;
    use crate::circuit::gadgets::AddConfig;
    use crate::constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain,
    };
    use crate::note::NoteCommitment;
    use crate::nullifier::Nullifier;
    use crate::user::NullifierDerivingKey;
    use ff::Field;
    use group::Curve;
    use halo2_gadgets::{
        ecc::chip::EccConfig,
        poseidon::{
            primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
        },
        sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{
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
