use ff::Field;
use halo2_gadgets::{
    poseidon::{
        primitives as poseidon, primitives::ConstantLength, Hash as PoseidonHash,
        Pow5Chip as PoseidonChip,
    },
    utilities::bool_check,
};
use halo2_proofs::{
    circuit::{floor_planner, AssignedCell, Layouter, Region, Value},
    plonk::{
        keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Constraints, Error,
        Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;
use taiga_halo2::{
    circuit::{
        gadgets::{assign_free_advice, target_note_variable::GetTargetNoteVariableConfig},
        integrity::{OutputNoteVar, SpendNoteVar},
        note_circuit::NoteConfig,
        vp_circuit::{
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
    proof::Proof,
    utils::poseidon_hash,
    vp_circuit_impl,
    vp_vk::ValidityPredicateVerifyingKey,
};

#[derive(Clone, Debug, Default)]
struct DealerIntentValidityPredicateCircuit {
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // The note that vp owned is set at spend_notes[0] or output_notes[0] by default. Make it mandatory later.
    // is_spend_note helps locate the target note in spend_notes and output_notes.
    is_spend_note: pallas::Base,
    encoded_puzzle: pallas::Base,
    sudoku_app_vk: pallas::Base,
    // When it's an output note, we don't need a valid solution.
    encoded_solution: pallas::Base,
}

#[derive(Clone, Debug)]
struct IntentAppValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    get_target_variable_config: GetTargetNoteVariableConfig,
    dealer_intent_check_config: DealerIntentCheckConfig,
}

impl ValidityPredicateConfig for IntentAppValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let instances = note_conifg.instances;
        let get_target_variable_config = GetTargetNoteVariableConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3],
        );
        let dealer_intent_check_config = DealerIntentCheckConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
        );

        Self {
            note_conifg,
            advices,
            instances,
            get_target_variable_config,
            dealer_intent_check_config,
        }
    }
}

impl DealerIntentValidityPredicateCircuit {
    #![allow(dead_code)]
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let mut output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let is_spend_note = pallas::Base::zero();
        let encoded_puzzle = pallas::Base::random(&mut rng);
        let sudoku_app_vk = ValidityPredicateVerifyingKey::dummy(&mut rng).get_compressed();
        output_notes[0].note_type.app_data = Self::compute_app_data(encoded_puzzle, sudoku_app_vk);
        let encoded_solution = pallas::Base::random(&mut rng);
        Self {
            spend_notes,
            output_notes,
            is_spend_note,
            encoded_puzzle,
            sudoku_app_vk,
            encoded_solution,
        }
    }

    pub fn compute_app_data(
        encoded_puzzle: pallas::Base,
        sudoku_app_vk: pallas::Base,
    ) -> pallas::Base {
        poseidon_hash(encoded_puzzle, sudoku_app_vk)
    }

    fn dealer_intent_check(
        &self,
        config: &IntentAppValidityPredicateConfig,
        mut layouter: impl Layouter<pallas::Base>,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        encoded_puzzle: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk_in_dealer_intent_note: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_note: &OutputNoteVar,
    ) -> Result<(), Error> {
        // puzzle_note_app_data = poseidon_hash(encoded_puzzle || encoded_solution)
        let encoded_solution = assign_free_advice(
            layouter.namespace(|| "witness encoded_solution"),
            config.advices[0],
            Value::known(self.encoded_solution),
        )?;
        let encoded_puzzle_note_app_data = {
            let poseidon_config = config.get_note_config().poseidon_config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [encoded_puzzle.clone(), encoded_solution];
            poseidon_hasher.hash(
                layouter.namespace(|| "check app_data encoding"),
                poseidon_message,
            )?
        };

        layouter.assign_region(
            || "dealer intent check",
            |mut region| {
                config.dealer_intent_check_config.assign_region(
                    is_spend_note,
                    &puzzle_note.value,
                    &puzzle_note.app_vk,
                    sudoku_app_vk_in_dealer_intent_note,
                    &puzzle_note.app_data,
                    &encoded_puzzle_note_app_data,
                    0,
                    &mut region,
                )
            },
        )?;
        Ok(())
    }
}

impl ValidityPredicateInfo for DealerIntentValidityPredicateCircuit {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();
        instances.push(self.is_spend_note);

        instances
    }

    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
        let instance = self.get_instances();
        let proof = Proof::create(&pk, params, self.clone(), &[&instance], &mut rng).unwrap();
        VPVerifyingInfo {
            vk,
            proof,
            instance,
        }
    }

    fn get_vp_description(&self) -> ValidityPredicateVerifyingKey {
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
    }
}

impl ValidityPredicateCircuit for DealerIntentValidityPredicateCircuit {
    type VPConfig = IntentAppValidityPredicateConfig;
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::VPConfig,
        mut layouter: impl Layouter<pallas::Base>,
        spend_note_variables: &[SpendNoteVar],
        output_note_variables: &[OutputNoteVar],
    ) -> Result<(), Error> {
        let is_spend_note = assign_free_advice(
            layouter.namespace(|| "witness is_spend_note"),
            config.advices[0],
            Value::known(self.is_spend_note),
        )?;

        // publicize is_spend_note and check it outside of circuit.
        layouter.constrain_instance(is_spend_note.cell(), config.instances, 2 * NUM_NOTE)?;

        // search target note and output the app_data
        let app_data = layouter.assign_region(
            || "get target app_data",
            |mut region| {
                config.get_target_variable_config.assign_region(
                    &is_spend_note,
                    &spend_note_variables[0].app_data,
                    &output_note_variables[0].app_data,
                    0,
                    &mut region,
                )
            },
        )?;

        // app_data = poseidon_hash(encoded_puzzle || sudoku_app_vk)
        let encoded_puzzle = assign_free_advice(
            layouter.namespace(|| "witness encoded_puzzle"),
            config.advices[0],
            Value::known(self.encoded_puzzle),
        )?;
        let sudoku_app_vk = assign_free_advice(
            layouter.namespace(|| "witness sudoku_app_vk"),
            config.advices[0],
            Value::known(self.sudoku_app_vk),
        )?;
        let app_data_encode = {
            let poseidon_config = config.get_note_config().poseidon_config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [encoded_puzzle.clone(), sudoku_app_vk.clone()];
            poseidon_hasher.hash(
                layouter.namespace(|| "check app_data encoding"),
                poseidon_message,
            )?
        };

        layouter.assign_region(
            || "check app_data encoding",
            |mut region| region.constrain_equal(app_data_encode.cell(), app_data.cell()),
        )?;

        // if it is an output note, do nothing
        // if it is a spend note, 1. check the zero value of puzzle_note; 2. check the puzzle equality.
        self.dealer_intent_check(
            &config,
            layouter.namespace(|| "dealer intent check"),
            &is_spend_note,
            &encoded_puzzle,
            &sudoku_app_vk,
            &output_note_variables[0],
        )
    }
}

vp_circuit_impl!(DealerIntentValidityPredicateCircuit);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerIntentCheckConfig {
    q_dealer_intent_check: Selector,
    is_spend_note: Column<Advice>,
    puzzle_note_value: Column<Advice>,
    sudoku_app_vk: Column<Advice>,
    sudoku_app_vk_in_dealer_intent_note: Column<Advice>,
    puzzle_note_app_data: Column<Advice>,
    encoded_puzzle_note_app_data: Column<Advice>,
}

impl DealerIntentCheckConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_spend_note: Column<Advice>,
        puzzle_note_value: Column<Advice>,
        sudoku_app_vk: Column<Advice>,
        sudoku_app_vk_in_dealer_intent_note: Column<Advice>,
        puzzle_note_app_data: Column<Advice>,
        encoded_puzzle_note_app_data: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_spend_note);
        meta.enable_equality(puzzle_note_value);
        meta.enable_equality(sudoku_app_vk);
        meta.enable_equality(sudoku_app_vk_in_dealer_intent_note);
        meta.enable_equality(puzzle_note_app_data);
        meta.enable_equality(encoded_puzzle_note_app_data);

        let config = Self {
            q_dealer_intent_check: meta.selector(),
            is_spend_note,
            puzzle_note_value,
            sudoku_app_vk,
            sudoku_app_vk_in_dealer_intent_note,
            puzzle_note_app_data,
            encoded_puzzle_note_app_data,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check dealer intent", |meta| {
            let q_dealer_intent_check = meta.query_selector(self.q_dealer_intent_check);
            let is_spend_note = meta.query_advice(self.is_spend_note, Rotation::cur());
            let puzzle_note_value = meta.query_advice(self.puzzle_note_value, Rotation::cur());
            let sudoku_app_vk = meta.query_advice(self.sudoku_app_vk, Rotation::cur());
            let sudoku_app_vk_in_dealer_intent_note =
                meta.query_advice(self.sudoku_app_vk_in_dealer_intent_note, Rotation::cur());
            let puzzle_note_app_data =
                meta.query_advice(self.puzzle_note_app_data, Rotation::cur());
            let encoded_puzzle_note_app_data =
                meta.query_advice(self.encoded_puzzle_note_app_data, Rotation::cur());

            let bool_check_is_spend = bool_check(is_spend_note.clone());

            Constraints::with_selector(
                q_dealer_intent_check,
                [
                    ("bool_check_is_spend", bool_check_is_spend),
                    (
                        "check zero value of puzzle note",
                        is_spend_note.clone() * puzzle_note_value,
                    ),
                    (
                        "check sudoku_app_vk",
                        is_spend_note.clone()
                            * (sudoku_app_vk - sudoku_app_vk_in_dealer_intent_note),
                    ),
                    (
                        "check puzzle note app_data encoding",
                        is_spend_note * (puzzle_note_app_data - encoded_puzzle_note_app_data),
                    ),
                ],
            )
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_region(
        &self,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_note_value: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk_in_dealer_intent_note: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_note_app_data: &AssignedCell<pallas::Base, pallas::Base>,
        encoded_puzzle_note_app_data: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_dealer_intent_check` selector
        self.q_dealer_intent_check.enable(region, offset)?;

        is_spend_note.copy_advice(|| "is_spend_notex", region, self.is_spend_note, offset)?;
        puzzle_note_value.copy_advice(
            || "puzzle_note_value",
            region,
            self.puzzle_note_value,
            offset,
        )?;
        sudoku_app_vk.copy_advice(|| "sudoku_app_vk", region, self.sudoku_app_vk, offset)?;
        sudoku_app_vk_in_dealer_intent_note.copy_advice(
            || "sudoku_app_vk_in_dealer_intent_note",
            region,
            self.sudoku_app_vk_in_dealer_intent_note,
            offset,
        )?;
        puzzle_note_app_data.copy_advice(
            || "puzzle_note_app_data",
            region,
            self.puzzle_note_app_data,
            offset,
        )?;
        encoded_puzzle_note_app_data.copy_advice(
            || "encoded_puzzle_note_app_data",
            region,
            self.encoded_puzzle_note_app_data,
            offset,
        )?;

        Ok(())
    }
}

#[test]
fn test_halo2_dealer_intent_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = DealerIntentValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
