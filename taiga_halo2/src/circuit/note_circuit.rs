use crate::circuit::gadgets::{AddChip, AddConfig};
use crate::constant::{NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain};
use halo2_gadgets::{
    ecc::chip::EccConfig,
    ecc::{chip::EccChip, Point, ScalarFixed},
    poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig},
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        CommitDomain, Message, MessagePiece,
    },
    utilities::{lookup_range_check::LookupRangeCheckConfig, RangeConstrained},
};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::{arithmetic::FieldExt, pallas};

type NoteCommitPiece = MessagePiece<
    CP::InnerCurve,
    SinsemillaChip<NoteCommitmentHashDomain, NoteCommitmentDomain, NoteCommitmentFixedBases>,
    10,
    253,
>;

/// bit10 = (bits 250..=255) || (bits 0..=4)
///
/// | A_6 | A_7 | A_8 | q_notecommit_5_5 |
/// ------------------------------------
/// | bit10 | bit5 | bit5_2 |       1        |
///
#[derive(Clone, Debug)]
struct Decompose5_5 {
    q_notecommit_5_5: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl Decompose5_5 {
    fn configure(
        meta: &mut ConstraintSystem<CP::CurveScalarField>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        two_pow_5: CP::CurveScalarField,
    ) -> Self {
        let q_notecommit_5_5 = meta.selector();

        meta.create_gate("NoteCommit MessagePiece bit10", |meta| {
            let q_notecommit_5_5 = meta.query_selector(q_notecommit_5_5);

            // bit10 has been constrained to 10 bits by the Sinsemilla hash.
            let bit10 = meta.query_advice(col_l, Rotation::cur());
            // bit5 has been constrained to 5 bits outside this gate.
            let bit5 = meta.query_advice(col_m, Rotation::cur());
            // bit5_2 has been constrained to 5 bits outside this gate.
            let bit5_2 = meta.query_advice(col_r, Rotation::cur());

            // bit10 = bit5 + (2^5) bit5_2
            let decomposition_check = bit10 - (bit5 + bit5_2 * two_pow_5);

            Constraints::with_selector(
                q_notecommit_5_5,
                Some(("decomposition", decomposition_check)),
            )
        });

        Self {
            q_notecommit_5_5,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<CP::CurveScalarField, 10>,
        chip: SinsemillaChip<
            NoteCommitmentHashDomain,
            NoteCommitmentDomain,
            NoteCommitmentFixedBases,
        >,
        layouter: &mut impl Layouter<CP::CurveScalarField>,
        first: &AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
        second: &AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<CP::CurveScalarField, AssignedCell<CP::CurveScalarField, CP::CurveScalarField>>,
            RangeConstrained<CP::CurveScalarField, AssignedCell<CP::CurveScalarField, CP::CurveScalarField>>,
        ),
        Error,
    > {
        // Constrain bit5 to be 5 bits.
        let bit5 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "bit5"),
            first.value(),
            250..255,
        )?;

        // Constrain bit5_2 to be 5 bits.
        let bit5_2 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "bit5_2"),
            second.value(),
            0..5,
        )?;

        let bit10 = MessagePiece::from_subpieces(
            chip,
            layouter.namespace(|| "bit10"),
            [bit5.value(), bit5_2.value()],
        )?;

        Ok((bit10, bit5, bit5_2))
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<CP::CurveScalarField>,
        bit10: NoteCommitPiece,
        bit5: RangeConstrained<CP::CurveScalarField, AssignedCell<CP::CurveScalarField, CP::CurveScalarField>>,
        bit5_2: RangeConstrained<CP::CurveScalarField, AssignedCell<CP::CurveScalarField, CP::CurveScalarField>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit MessagePiece bit10",
            |mut region| {
                self.q_notecommit_5_5.enable(&mut region, 0)?;

                bit10
                    .inner()
                    .cell_value()
                    .copy_advice(|| "bit10", &mut region, self.col_l, 0)?;
                bit5.inner()
                    .copy_advice(|| "bit5", &mut region, self.col_m, 0)?;
                bit5_2
                    .inner()
                    .copy_advice(|| "bit5_2", &mut region, self.col_r, 0)?;

                Ok(())
            },
        )
    }
}

/// |  A_6  | A_7 | A_8 | q_base_250_5 |
/// ------------------------------------------------
/// |  v  | v_250 | v_5 |          1         |
///
#[derive(Clone, Debug)]
struct BaseCanonicity250_5 {
    q_base_250_5: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl BaseCanonicity250_5 {
    fn configure(
        meta: &mut ConstraintSystem<CP::CurveScalarField>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        two_pow_250: CP::CurveScalarField,
    ) -> Self {
        let q_base_250_5 = meta.selector();

        meta.create_gate("NoteCommit input value", |meta| {
            let q_base_250_5 = meta.query_selector(q_base_250_5);

            let value = meta.query_advice(col_l, Rotation::cur());
            // v_250 has been constrained to 250 bits.
            let v_250 = meta.query_advice(col_m, Rotation::cur());
            // v_5 has been constrained to 5 bits.
            let v_5 = meta.query_advice(col_r, Rotation::cur());

            // value = v_250 + (2^250)v_5
            let value_check = v_250 + v_5 * two_pow_250 - value;

            Constraints::with_selector(q_base_250_5, Some(("value_check", value_check)))
        });

        Self {
            q_base_250_5,
            col_l,
            col_m,
            col_r,
        }
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<CP::CurveScalarField>,
        value: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
        v_250: NoteCommitPiece,
        v_5: RangeConstrained<CP::CurveScalarField, AssignedCell<CP::CurveScalarField, CP::CurveScalarField>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input value",
            |mut region| {
                value.copy_advice(|| "value", &mut region, self.col_l, 0)?;
                v_250
                    .inner()
                    .cell_value()
                    .copy_advice(|| "v_250", &mut region, self.col_m, 0)?;
                v_5.inner()
                    .copy_advice(|| "v_5", &mut region, self.col_r, 0)?;
                self.q_base_250_5.enable(&mut region, 0)
            },
        )
    }
}

/// |  A_6  | A_7 | A_8 | q_base_250_5 |
/// ------------------------------------------------
/// |  v  | v_tail | v_5 |          1         |
///
#[derive(Clone, Debug)]
struct BaseCanonicity5 {
    q_base_5: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl BaseCanonicity5 {
    fn configure(
        meta: &mut ConstraintSystem<CP::CurveScalarField>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        two_pow_5: CP::CurveScalarField,
    ) -> Self {
        let q_base_5 = meta.selector();

        meta.create_gate("NoteCommit input value", |meta| {
            let q_base_5 = meta.query_selector(q_base_5);

            let value = meta.query_advice(col_l, Rotation::cur());
            // v_tail has been constrained to the tail bits.
            let v_tail = meta.query_advice(col_m, Rotation::cur());
            // v_5 has been constrained to the previous 5 bits.
            let v_5 = meta.query_advice(col_r, Rotation::cur());

            // value = v_tail * (2^5) + v_5
            let value_check = v_tail * two_pow_5 + v_5 - value;

            Constraints::with_selector(q_base_5, Some(("value_check", value_check)))
        });

        Self {
            q_base_5,
            col_l,
            col_m,
            col_r,
        }
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<CP::CurveScalarField>,
        value: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
        v_tail: NoteCommitPiece,
        v_5: RangeConstrained<CP::CurveScalarField, AssignedCell<CP::CurveScalarField, CP::CurveScalarField>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input value",
            |mut region| {
                value.copy_advice(|| "value", &mut region, self.col_l, 0)?;
                v_tail
                    .inner()
                    .cell_value()
                    .copy_advice(|| "v_tail", &mut region, self.col_m, 0)?;
                v_5.inner()
                    .copy_advice(|| "v_5", &mut region, self.col_r, 0)?;
                self.q_base_5.enable(&mut region, 0)
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct NoteCommitmentConfig {
    advices: [Column<Advice>; 10],
    decompose5_5: Decompose5_5,
    base_canonicity_250_5: BaseCanonicity250_5,
    base_canonicity_5: BaseCanonicity5,
    pub sinsemilla_config:
        SinsemillaConfig<NoteCommitmentHashDomain, NoteCommitmentDomain, NoteCommitmentFixedBases>,
}

#[derive(Clone, Debug)]
pub struct NoteCommitmentChip {
    config: NoteCommitmentConfig,
}

impl NoteCommitmentChip {
    pub fn configure(
        meta: &mut ConstraintSystem<CP::CurveScalarField>,
        advices: [Column<Advice>; 10],
        sinsemilla_config: SinsemillaConfig<
            NoteCommitmentHashDomain,
            NoteCommitmentDomain,
            NoteCommitmentFixedBases,
        >,
    ) -> NoteCommitmentConfig {
        let two_pow_5 = CP::CurveScalarField::from(1 << 5);
        let two_pow_250 = CP::CurveScalarField::from_u128(1 << 125).square();

        let col_l = advices[6];
        let col_m = advices[7];
        let col_r = advices[8];

        // Decompose configure
        let decompose5_5 = Decompose5_5::configure(meta, col_l, col_m, col_r, two_pow_5);

        // Base canonicity configure
        let base_canonicity_250_5 =
            BaseCanonicity250_5::configure(meta, col_l, col_m, col_r, two_pow_250);
        let base_canonicity_5 = BaseCanonicity5::configure(meta, col_l, col_m, col_r, two_pow_5);

        NoteCommitmentConfig {
            decompose5_5,
            base_canonicity_250_5,
            base_canonicity_5,
            advices,
            sinsemilla_config,
        }
    }

    pub fn construct(config: NoteCommitmentConfig) -> Self {
        Self { config }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn note_commitment_gadget(
    mut layouter: impl Layouter<CP::CurveScalarField>,
    chip: SinsemillaChip<NoteCommitmentHashDomain, NoteCommitmentDomain, NoteCommitmentFixedBases>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    note_commit_chip: NoteCommitmentChip,
    user_address: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    app_address: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    data: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    rho: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    psi: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    value: AssignedCell<CP::CurveScalarField, CP::CurveScalarField>,
    rcm: ScalarFixed<CP::InnerCurve, EccChip<NoteCommitmentFixedBases>>,
) -> Result<Point<CP::InnerCurve, EccChip<NoteCommitmentFixedBases>>, Error> {
    let lookup_config = chip.config().lookup_config();

    // `user_0_249` = bits 0..=249 of `user_address`
    let user_0_249 = MessagePiece::from_subpieces(
        chip.clone(),
        layouter.namespace(|| "user_0_249"),
        [RangeConstrained::bitrange_of(user_address.value(), 0..250)],
    )?;

    // `a` = (bits 250..=255 of user) || (bits 0..=4 of app)
    let (a, user_tail_bit5, app_pre_bit5) = Decompose5_5::decompose(
        &lookup_config,
        chip.clone(),
        &mut layouter,
        &user_address,
        &app_address,
    )?;

    // `app_5_254` = bits 5..=254 of `app`
    let app_5_254 = MessagePiece::from_subpieces(
        chip.clone(),
        layouter.namespace(|| "app_5_254"),
        [RangeConstrained::bitrange_of(app_address.value(), 5..255)],
    )?;

    // `data_0_249` = bits 0..=249 of `data`
    let data_0_249 = MessagePiece::from_subpieces(
        chip.clone(),
        layouter.namespace(|| "data_0_249"),
        [RangeConstrained::bitrange_of(data.value(), 0..250)],
    )?;

    // b = (bits 250..=255 of data) || (bits 0..=4 of rho)
    let (b, data_tail_bit5, rho_pre_bit5) =
        Decompose5_5::decompose(&lookup_config, chip.clone(), &mut layouter, &data, &rho)?;

    // `rho_5_254` = bits 5..=254 of `rho`
    let rho_5_254 = MessagePiece::from_subpieces(
        chip.clone(),
        layouter.namespace(|| "rho_5_254"),
        [RangeConstrained::bitrange_of(rho.value(), 5..255)],
    )?;

    // `psi_0_249` = bits 0..=249 of `psi`
    let psi_0_249 = MessagePiece::from_subpieces(
        chip.clone(),
        layouter.namespace(|| "psi_0_249"),
        [RangeConstrained::bitrange_of(psi.value(), 0..250)],
    )?;

    // `c` = (bits 250..=255 of psi) || (bits 0..=4 of value)
    let (c, psi_tail_bit5, value_pre_bit5) =
        Decompose5_5::decompose(&lookup_config, chip.clone(), &mut layouter, &psi, &value)?;

    // `d` = (bits 5..=63 of value) || 0
    let d = MessagePiece::from_subpieces(
        chip.clone(),
        layouter.namespace(|| "d"),
        [
            RangeConstrained::bitrange_of(value.value(), 5..64),
            RangeConstrained::bitrange_of(Value::known(&CP::CurveScalarField::zero()), 0..1),
        ],
    )?;

    // cm = NoteCommit^rcm(user_address || app_address || data || rho || psi || value)
    let (cm, _zs) = {
        let message = Message::from_pieces(
            chip.clone(),
            vec![
                user_0_249.clone(),
                a.clone(),
                app_5_254.clone(),
                data_0_249.clone(),
                b.clone(),
                rho_5_254.clone(),
                psi_0_249.clone(),
                c.clone(),
                d.clone(),
            ],
        );
        let domain = CommitDomain::new(chip, ecc_chip, &NoteCommitmentDomain);
        domain.commit(
            layouter.namespace(|| "Process NoteCommit inputs"),
            message,
            rcm,
        )?
    };

    // assign values
    let cfg = note_commit_chip.config;

    cfg.decompose5_5.assign(
        &mut layouter,
        a,
        user_tail_bit5.clone(),
        app_pre_bit5.clone(),
    )?;

    cfg.decompose5_5.assign(
        &mut layouter,
        b,
        data_tail_bit5.clone(),
        rho_pre_bit5.clone(),
    )?;

    cfg.decompose5_5.assign(
        &mut layouter,
        c,
        psi_tail_bit5.clone(),
        value_pre_bit5.clone(),
    )?;

    cfg.base_canonicity_250_5
        .assign(&mut layouter, user_address, user_0_249, user_tail_bit5)?;
    cfg.base_canonicity_5
        .assign(&mut layouter, app_address, app_5_254, app_pre_bit5)?;
    cfg.base_canonicity_250_5
        .assign(&mut layouter, data, data_0_249, data_tail_bit5)?;
    cfg.base_canonicity_5
        .assign(&mut layouter, rho, rho_5_254, rho_pre_bit5)?;
    cfg.base_canonicity_250_5
        .assign(&mut layouter, psi, psi_0_249, psi_tail_bit5)?;
    cfg.base_canonicity_5
        .assign(&mut layouter, value, d, value_pre_bit5)?;

    Ok(cm)
}

#[derive(Clone, Debug)]
pub struct NoteConfig {
    pub instances: Column<Instance>,
    pub advices: [Column<Advice>; 10],
    pub add_config: AddConfig,
    pub ecc_config: EccConfig<NoteCommitmentFixedBases>,
    pub poseidon_config: PoseidonConfig<CP::CurveScalarField, 3, 2>,
    pub sinsemilla_config:
        SinsemillaConfig<NoteCommitmentHashDomain, NoteCommitmentDomain, NoteCommitmentFixedBases>,
    pub note_commit_config: NoteCommitmentConfig,
}

#[derive(Clone, Debug)]
pub struct NoteChip {
    config: NoteConfig,
}

impl NoteChip {
    pub fn configure(
        meta: &mut ConstraintSystem<CP::CurveScalarField>,
        instances: Column<Instance>,
        advices: [Column<Advice>; 10],
    ) -> NoteConfig {
        let add_config = AddChip::configure(meta, advices[0..2].try_into().unwrap());

        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

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
        meta.enable_constant(lagrange_coeffs[0]);

        let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
            meta,
            advices,
            lagrange_coeffs,
            range_check,
        );

        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            lagrange_coeffs[2..5].try_into().unwrap(),
            lagrange_coeffs[5..8].try_into().unwrap(),
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

        let note_commit_config =
            NoteCommitmentChip::configure(meta, advices, sinsemilla_config.clone());

        NoteConfig {
            instances,
            advices,
            add_config,
            ecc_config,
            poseidon_config,
            sinsemilla_config,
            note_commit_config,
        }
    }

    pub fn construct(config: NoteConfig) -> Self {
        Self { config }
    }
}

#[test]
fn test_halo2_note_commitment_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use crate::note::Note;
    use crate::{app::App, nullifier::Nullifier, user::User};
    use ff::Field;
    use group::Curve;
    use halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            NonIdentityPoint, ScalarFixed,
        },
        sinsemilla::chip::SinsemillaChip,
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use rand::{rngs::OsRng, RngCore};

    use crate::circuit::circuit_parameters::DLCircuitParameters as CP;
    #[derive(Default)]
    struct MyCircuit {
        user: User<CP>,
        app: App,
        value: u64,
        rho: Nullifier<CP>,
        data: CP::CurveScalarField,
        rcm: CP::InnerCurveScalarField,
    }

    impl Circuit<CP::CurveScalarField> for MyCircuit {
        type Config = (NoteCommitmentConfig, EccConfig<NoteCommitmentFixedBases>);
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

            // Shared fixed column for loading constants.
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            for advice in advices.iter() {
                meta.enable_equality(*advice);
            }

            let table_idx = meta.lookup_table_column();
            let lookup = (
                table_idx,
                meta.lookup_table_column(),
                meta.lookup_table_column(),
            );
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

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
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
            let note_commit_config =
                NoteCommitmentChip::configure(meta, advices, sinsemilla_config);

            let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
                meta,
                advices,
                lagrange_coeffs,
                range_check,
            );

            (note_commit_config, ecc_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<CP::CurveScalarField>,
        ) -> Result<(), Error> {
            let (note_commit_config, ecc_config) = config;

            // Load the Sinsemilla generator lookup table used by the whole circuit.
            SinsemillaChip::<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >::load(note_commit_config.sinsemilla_config.clone(), &mut layouter)?;
            let note = Note::new(
                self.user.clone(),
                self.app.clone(),
                self.value,
                self.rho,
                self.data,
                self.rcm,
            );
            // Construct a Sinsemilla chip
            let sinsemilla_chip =
                SinsemillaChip::construct(note_commit_config.sinsemilla_config.clone());

            // Construct an ECC chip
            let ecc_chip = EccChip::construct(ecc_config);

            // Construct a NoteCommit chip
            let note_commit_chip = NoteCommitmentChip::construct(note_commit_config.clone());

            // Witness user
            let user_address = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                note_commit_config.advices[0],
                Value::known(note.user.address()),
            )?;

            // Witness app
            let app_address = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                note_commit_config.advices[0],
                Value::known(note.app.address()),
            )?;

            // Witness data
            let data = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                note_commit_config.advices[0],
                Value::known(note.data),
            )?;

            // Witness a random non-negative u64 note value
            // A note value cannot be negative.
            let value_var = {
                assign_free_advice(
                    layouter.namespace(|| "witness value"),
                    note_commit_config.advices[0],
                    Value::known(CP::CurveScalarField::from(note.value)),
                )?
            };

            // Witness rho
            let rho = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                note_commit_config.advices[0],
                Value::known(note.rho.inner()),
            )?;

            // Witness psi
            let psi = assign_free_advice(
                layouter.namespace(|| "witness psi"),
                note_commit_config.advices[0],
                Value::known(note.psi),
            )?;

            let rcm = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcm"),
                Value::known(note.rcm),
            )?;

            let cm = note_commitment_gadget(
                layouter.namespace(|| "Hash NoteCommit pieces"),
                sinsemilla_chip,
                ecc_chip.clone(),
                note_commit_chip,
                user_address,
                app_address,
                data,
                rho,
                psi,
                value_var,
                rcm,
            )?;
            let expected_cm = {
                let point = note.commitment().inner().to_affine();
                NonIdentityPoint::new(
                    ecc_chip,
                    layouter.namespace(|| "witness cm"),
                    Value::known(point),
                )?
            };
            cm.constrain_equal(layouter.namespace(|| "cm == expected cm"), &expected_cm)
        }
    }

    let mut rng = OsRng;
    let circuit = MyCircuit {
        user: User::dummy(&mut rng),
        app: App::dummy(&mut rng),
        value: rng.next_u64(),
        rho: Nullifier::default(),
        data: CP::CurveScalarField::random(&mut rng),
        rcm: CP::InnerCurveScalarField::random(&mut rng),
    };

    let prover = MockProver::<CP::CurveScalarField>::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
