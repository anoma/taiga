use crate::circuit::gadgets::{assign_free_advice, AddChip, AddInstructions};
use crate::circuit::note_circuit::{note_commitment_gadget, NoteCommitmentChip};
use crate::constant::{
    NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentFixedBasesFull,
    NoteCommitmentHashDomain, NullifierK,
};
use crate::note::Note;
use halo2_gadgets::{
    ecc::{chip::EccChip, FixedPoint, FixedPointBaseField, Point, ScalarFixed},
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

use super::circuit_parameters::CircuitParameters;

// cm is a point
#[allow(clippy::too_many_arguments)]
pub fn nullifier_circuit<CP: CircuitParameters>(
    mut layouter: impl Layouter<CP::CurveScalarField>,
    poseidon_chip: PoseidonChip<CP::CurveScalarField, 3, 2>,
    add_chip: AddChip<CP::CurveScalarField>,
    ecc_chip: EccChip<NoteCommitmentFixedBases<CP>>,
    nk: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    rho: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    psi: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    cm: &Point<CP::InnerCurve, EccChip<NoteCommitmentFixedBases<CP>>>,
) -> Result<AssignedCell<CP::CurveScalarField, CP::CurveScalarField>, Error> {
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
pub struct SpendNoteVar<CP: CircuitParameters> {
    pub user_address: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub app_address: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub value: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub data: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub nf: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub cm: Point<CP::InnerCurve, EccChip<NoteCommitmentFixedBases<CP>>>,
}

#[allow(clippy::too_many_arguments)]
pub fn check_spend_note<CP: CircuitParameters>(
    mut layouter: impl Layouter<CP::CurveScalarField>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    ecc_chip: EccChip<NoteCommitmentFixedBases<CP>>,
    sinsemilla_chip: SinsemillaChip<
        NoteCommitmentHashDomain<CP>,
        NoteCommitmentDomain<CP>,
        NoteCommitmentFixedBases<CP>,
    >,
    note_commit_chip: NoteCommitmentChip<CP>,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<CP::CurveScalarField, 3, 2>,
    // poseidon_chip: PoseidonChip<CP::CurveScalarField, 3, 2>,
    add_chip: AddChip<CP::CurveScalarField>,
    spend_note: Note<CP>,
    nf_row_idx: usize,
) -> Result<SpendNoteVar<CP>, Error> {
    // Check spend note user integrity: user_address = Com_r(Com_r(send_vp, nk), recv_vp_hash)
    let (user_address, nk) = {
        // Witness send_vp
        let send_vp = spend_note
            .user
            .send_com
            .get_send_vp()
            .unwrap()
            .get_compressed();
        let send_vp_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(send_vp),
        )?;

        // Witness nk
        let nk = spend_note.user.get_nk().unwrap();
        let nk_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(nk.inner()),
        )?;

        // send_com = Com_r(send_vp, nk)
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

        // Witness recv_vp_hash
        let recv_vp_hash_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(spend_note.user.recv_vp.get_compressed()),
        )?;

        // user_address = Com_r(send_com, recv_vp_hash_var)
        let user_address = {
            let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [send_com, recv_vp_hash_var];
            poseidon_hasher.hash(layouter.namespace(|| "user_address"), poseidon_message)?
        };

        (user_address, nk_var)
    };

    // Witness app_address
    let app_address = assign_free_advice(
        layouter.namespace(|| "witness app_address"),
        advices[0],
        Value::known(spend_note.app.address()),
    )?;

    // Witness data
    let data = assign_free_advice(
        layouter.namespace(|| "witness rho"),
        advices[0],
        Value::known(spend_note.data),
    )?;

    // Witness value(u64)
    let value = {
        assign_free_advice(
            layouter.namespace(|| "witness value"),
            advices[0],
            Value::known(CP::CurveScalarField::from(spend_note.value)),
        )?
    };

    // Witness rho
    let rho = assign_free_advice(
        layouter.namespace(|| "witness rho"),
        advices[0],
        Value::known(spend_note.rho.inner()),
    )?;

    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi"),
        advices[0],
        Value::known(spend_note.psi),
    )?;

    // Witness rcm
    let rcm = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "rcm"),
        Value::known(spend_note.rcm),
    )?;

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip.clone(),
        note_commit_chip,
        user_address.clone(),
        app_address.clone(),
        data.clone(),
        rho.clone(),
        psi.clone(),
        value.clone(),
        rcm,
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
        app_address,
        value,
        data,
        nf,
        cm,
    })
}

// Return variables in the spend note
#[derive(Debug)]
pub struct OutputNoteVar<CP: CircuitParameters> {
    pub user_address: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub app_address: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub value: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub data: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    pub cm: Point<CP::InnerCurve, EccChip<NoteCommitmentFixedBases<CP>>>,
}

#[allow(clippy::too_many_arguments)]
pub fn check_output_note<CP: CircuitParameters>(
    mut layouter: impl Layouter<CP::CurveScalarField>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    ecc_chip: EccChip<NoteCommitmentFixedBases<CP>>,
    sinsemilla_chip: SinsemillaChip<
        NoteCommitmentHashDomain<CP>,
        NoteCommitmentDomain<CP>,
        NoteCommitmentFixedBases<CP>,
    >,
    note_commit_chip: NoteCommitmentChip<CP>,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<CP::CurveScalarField, 3, 2>,
    // poseidon_chip: PoseidonChip<CP::CurveScalarField, 3, 2>,
    output_note: Note<CP>,
    old_nf: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    cm_row_idx: usize,
) -> Result<OutputNoteVar<CP>, Error> {
    // Check output note user integrity: user_address = Com_r(, recv_vp_hash)
    let user_address = {
        let send_com = assign_free_advice(
            layouter.namespace(|| "witness output send_com"),
            advices[0],
            Value::known(output_note.user.send_com.get_closed()),
        )?;
        // Witness recv_vp_hash
        let recv_vp_hash_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(output_note.user.recv_vp.get_compressed()),
        )?;

        let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
        let poseidon_hasher =
            PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                poseidon_chip,
                layouter.namespace(|| "Poseidon init"),
            )?;
        let poseidon_message = [send_com, recv_vp_hash_var];
        poseidon_hasher.hash(layouter.namespace(|| "user_address"), poseidon_message)?
    };

    // Witness app_address
    let app_address = assign_free_advice(
        layouter.namespace(|| "witness app_address"),
        advices[0],
        Value::known(output_note.app.address()),
    )?;

    // Witness data
    let data = assign_free_advice(
        layouter.namespace(|| "witness data"),
        advices[0],
        Value::known(output_note.data),
    )?;

    // Witness value(u64)
    let value = {
        assign_free_advice(
            layouter.namespace(|| "witness value"),
            advices[0],
            Value::known(CP::CurveScalarField::from(output_note.value)),
        )?
    };

    // Witness rcm
    let rcm = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "rcm"),
        Value::known(output_note.rcm),
    )?;

    // Derive psi: psi = poseidon_hash(rho, (rcm * generator).x)
    let psi = {
        let generator = FixedPoint::from_inner(ecc_chip.clone(), NoteCommitmentFixedBasesFull);
        let (rcm_mul_gen, _) = generator.mul(layouter.namespace(|| "rcm * generator"), &rcm)?;
        let rcm_mul_gen_x = rcm_mul_gen.extract_p().inner().clone();
        let poseidon_chip = PoseidonChip::construct(poseidon_config);
        let poseidon_hasher =
            PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                poseidon_chip,
                layouter.namespace(|| "Poseidon init"),
            )?;
        let poseidon_message = [old_nf.clone(), rcm_mul_gen_x];
        poseidon_hasher.hash(layouter.namespace(|| "user_address"), poseidon_message)?
    };

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip,
        note_commit_chip,
        user_address.clone(),
        app_address.clone(),
        data.clone(),
        old_nf,
        psi,
        value.clone(),
        rcm,
    )?;

    // Public cm
    let cm_x = cm.extract_p().inner().clone();
    layouter.constrain_instance(cm_x.cell(), instances, cm_row_idx)?;

    Ok(OutputNoteVar {
        user_address,
        app_address,
        value,
        data,
        cm,
    })
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
    struct MyCircuit<CP: CircuitParameters> {
        nk: NullifierDerivingKey<CP>,
        rho: CP::CurveScalarField,
        psi: CP::CurveScalarField,
        cm: NoteCommitment<CP>,
    }

    impl<CP: CircuitParameters> Circuit<CP::CurveScalarField> for MyCircuit<CP> {
        type Config = (
            [Column<Advice>; 10],
            PoseidonConfig<CP::CurveScalarField, 3, 2>,
            AddConfig,
            EccConfig<NoteCommitmentFixedBases<CP>>,
            // add SinsemillaConfig to load look table, just for test
            SinsemillaConfig<
                NoteCommitmentHashDomain<CP>,
                NoteCommitmentDomain<CP>,
                NoteCommitmentFixedBases<CP>,
            >,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> Self::Config {
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
                NoteCommitmentHashDomain<CP>,
                NoteCommitmentDomain<CP>,
                NoteCommitmentFixedBases<CP>,
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
            mut layouter: impl Layouter<CP::CurveScalarField>,
        ) -> Result<(), Error> {
            let (advices, poseidon_config, add_config, ecc_config, sinsemilla_config) = config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let ecc_chip = EccChip::construct(ecc_config);
            let add_chip = AddChip::<CP::CurveScalarField>::construct(add_config, ());
            SinsemillaChip::<
                NoteCommitmentHashDomain<CP>,
                NoteCommitmentDomain<CP>,
                NoteCommitmentFixedBases<CP>,
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
    use crate::circuit::circuit_parameters::DLCircuitParameters as CP;
    let circuit = MyCircuit {
        nk: NullifierDerivingKey::rand(&mut rng),
        rho: CP::CurveScalarField::random(&mut rng),
        psi: CP::CurveScalarField::random(&mut rng),
        cm: NoteCommitment::default(),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
