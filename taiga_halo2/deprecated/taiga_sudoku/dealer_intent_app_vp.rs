use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    circuit::{floor_planner, AssignedCell, Layouter, Region, Value},
    plonk::{
        keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Constraints, Error,
        Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;
use taiga_halo2::{
    circuit::{
        gadgets::{
            assign_free_advice,
            poseidon_hash::poseidon_hash_gadget,
            target_note_variable::{
                get_is_input_note_flag, get_owned_note_variable, GetIsInputNoteFlagConfig,
                GetOwnedNoteVariableConfig,
            },
        },
        note_circuit::NoteConfig,
        vp_circuit::{
            BasicValidityPredicateVariables, OutputNoteVariables, VPVerifyingInfo,
            ValidityPredicateCircuit, ValidityPredicateConfig, ValidityPredicateInfo,
            ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    proof::Proof,
    utils::poseidon_hash,
    vp_circuit_impl,
    vp_vk::ValidityPredicateVerifyingKey,
};

#[derive(Clone, Debug, Default)]
struct DealerIntentValidityPredicateCircuit {
    owned_note_pub_id: pallas::Base,
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    encoded_puzzle: pallas::Base,
    sudoku_app_vk: pallas::Base,
    // When it's an output note, we don't need a valid solution.
    encoded_solution: pallas::Base,
}

#[derive(Clone, Debug)]
struct IntentAppValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    get_owned_note_variable_config: GetOwnedNoteVariableConfig,
    get_is_input_note_flag_config: GetIsInputNoteFlagConfig,
    dealer_intent_check_config: DealerIntentCheckConfig,
}

impl ValidityPredicateConfig for IntentAppValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let get_owned_note_variable_config = GetOwnedNoteVariableConfig::configure(
            meta,
            advices[0],
            [advices[1], advices[2], advices[3], advices[4]],
        );
        let dealer_intent_check_config = DealerIntentCheckConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
        );
        let get_is_input_note_flag_config =
            GetIsInputNoteFlagConfig::configure(meta, advices[0], advices[1], advices[2]);

        Self {
            note_conifg,
            advices,
            get_owned_note_variable_config,
            get_is_input_note_flag_config,
            dealer_intent_check_config,
        }
    }
}

impl DealerIntentValidityPredicateCircuit {
    #![allow(dead_code)]
    pub fn compute_app_data_static(
        encoded_puzzle: pallas::Base,
        sudoku_app_vk: pallas::Base,
    ) -> pallas::Base {
        poseidon_hash(encoded_puzzle, sudoku_app_vk)
    }

    fn dealer_intent_check(
        &self,
        config: &IntentAppValidityPredicateConfig,
        mut layouter: impl Layouter<pallas::Base>,
        is_input_note: &AssignedCell<pallas::Base, pallas::Base>,
        encoded_puzzle: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk_in_dealer_intent_note: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_note: &OutputNoteVariables,
    ) -> Result<(), Error> {
        // puzzle_note_app_data_static = poseidon_hash(encoded_puzzle || encoded_solution)
        let encoded_solution = assign_free_advice(
            layouter.namespace(|| "witness encoded_solution"),
            config.advices[0],
            Value::known(self.encoded_solution),
        )?;
        let encoded_puzzle_note_app_data_static = poseidon_hash_gadget(
            config.get_note_config().poseidon_config,
            layouter.namespace(|| "app_data_static encoding"),
            [encoded_puzzle.clone(), encoded_solution],
        )?;

        layouter.assign_region(
            || "dealer intent check",
            |mut region| {
                config.dealer_intent_check_config.assign_region(
                    is_input_note,
                    &puzzle_note.note_variables.value,
                    &puzzle_note.note_variables.app_vk,
                    sudoku_app_vk_in_dealer_intent_note,
                    &puzzle_note.note_variables.app_data_static,
                    &encoded_puzzle_note_app_data_static,
                    0,
                    &mut region,
                )
            },
        )?;
        Ok(())
    }
}

impl ValidityPredicateInfo for DealerIntentValidityPredicateCircuit {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let padding = ValidityPredicatePublicInputs::get_public_input_padding(
            public_inputs.len(),
            &RandomSeed::random(&mut rng),
        );
        public_inputs.extend(padding);
        public_inputs.into()
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

impl ValidityPredicateCircuit for DealerIntentValidityPredicateCircuit {
    type VPConfig = IntentAppValidityPredicateConfig;
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::VPConfig,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        let owned_note_pub_id = basic_variables.get_owned_note_pub_id();
        let is_input_note = get_is_input_note_flag(
            config.get_is_input_note_flag_config,
            layouter.namespace(|| "get is_input_note_flag"),
            &owned_note_pub_id,
            &basic_variables.get_input_note_nfs(),
            &basic_variables.get_output_note_cms(),
        )?;

        // search target note and output the app_static_data
        let app_data_static = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_static_data"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // app_data_static = poseidon_hash(encoded_puzzle || sudoku_app_vk)
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
        let app_data_static_encode = poseidon_hash_gadget(
            config.get_note_config().poseidon_config,
            layouter.namespace(|| "app_data_static encoding"),
            [encoded_puzzle.clone(), sudoku_app_vk.clone()],
        )?;

        layouter.assign_region(
            || "check app_data_static encoding",
            |mut region| {
                region.constrain_equal(app_data_static_encode.cell(), app_data_static.cell())
            },
        )?;

        // if it is an output note, do nothing
        // if it is an input note, 1. check the zero value of puzzle_note; 2. check the puzzle equality.
        self.dealer_intent_check(
            &config,
            layouter.namespace(|| "dealer intent check"),
            &is_input_note,
            &encoded_puzzle,
            &sudoku_app_vk,
            &basic_variables.output_note_variables[0],
        )
    }
}

vp_circuit_impl!(DealerIntentValidityPredicateCircuit);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerIntentCheckConfig {
    q_dealer_intent_check: Selector,
    is_input_note: Column<Advice>,
    puzzle_note_value: Column<Advice>,
    sudoku_app_vk: Column<Advice>,
    sudoku_app_vk_in_dealer_intent_note: Column<Advice>,
    puzzle_note_app_data_static: Column<Advice>,
    encoded_puzzle_note_app_data_static: Column<Advice>,
}

impl DealerIntentCheckConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_input_note: Column<Advice>,
        puzzle_note_value: Column<Advice>,
        sudoku_app_vk: Column<Advice>,
        sudoku_app_vk_in_dealer_intent_note: Column<Advice>,
        puzzle_note_app_data_static: Column<Advice>,
        encoded_puzzle_note_app_data_static: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_input_note);
        meta.enable_equality(puzzle_note_value);
        meta.enable_equality(sudoku_app_vk);
        meta.enable_equality(sudoku_app_vk_in_dealer_intent_note);
        meta.enable_equality(puzzle_note_app_data_static);
        meta.enable_equality(encoded_puzzle_note_app_data_static);

        let config = Self {
            q_dealer_intent_check: meta.selector(),
            is_input_note,
            puzzle_note_value,
            sudoku_app_vk,
            sudoku_app_vk_in_dealer_intent_note,
            puzzle_note_app_data_static,
            encoded_puzzle_note_app_data_static,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check dealer intent", |meta| {
            let q_dealer_intent_check = meta.query_selector(self.q_dealer_intent_check);
            let is_input_note = meta.query_advice(self.is_input_note, Rotation::cur());
            let puzzle_note_value = meta.query_advice(self.puzzle_note_value, Rotation::cur());
            let sudoku_app_vk = meta.query_advice(self.sudoku_app_vk, Rotation::cur());
            let sudoku_app_vk_in_dealer_intent_note =
                meta.query_advice(self.sudoku_app_vk_in_dealer_intent_note, Rotation::cur());
            let puzzle_note_app_data_static =
                meta.query_advice(self.puzzle_note_app_data_static, Rotation::cur());
            let encoded_puzzle_note_app_data_static =
                meta.query_advice(self.encoded_puzzle_note_app_data_static, Rotation::cur());

            let bool_check_is_input = bool_check(is_input_note.clone());

            Constraints::with_selector(
                q_dealer_intent_check,
                [
                    ("bool_check_is_input", bool_check_is_input),
                    (
                        "check zero value of puzzle note",
                        is_input_note.clone() * puzzle_note_value,
                    ),
                    (
                        "check sudoku_app_vk",
                        is_input_note.clone()
                            * (sudoku_app_vk - sudoku_app_vk_in_dealer_intent_note),
                    ),
                    (
                        "check puzzle note app_data_static encoding",
                        is_input_note
                            * (puzzle_note_app_data_static - encoded_puzzle_note_app_data_static),
                    ),
                ],
            )
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_region(
        &self,
        is_input_note: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_note_value: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk_in_dealer_intent_note: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_note_app_data_static: &AssignedCell<pallas::Base, pallas::Base>,
        encoded_puzzle_note_app_data_static: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_dealer_intent_check` selector
        self.q_dealer_intent_check.enable(region, offset)?;

        is_input_note.copy_advice(|| "is_input_note", region, self.is_input_note, offset)?;
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
        puzzle_note_app_data_static.copy_advice(
            || "puzzle_note_app_data_static",
            region,
            self.puzzle_note_app_data_static,
            offset,
        )?;
        encoded_puzzle_note_app_data_static.copy_advice(
            || "encoded_puzzle_note_app_data_static",
            region,
            self.encoded_puzzle_note_app_data_static,
            offset,
        )?;

        Ok(())
    }
}

#[test]
fn test_halo2_dealer_intent_vp_circuit() {
    use crate::app_vp::tests::{random_input_note, random_output_note};
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let input_notes = [(); NUM_NOTE].map(|_| random_input_note(&mut rng));
        let mut output_notes = input_notes
            .iter()
            .map(|input| random_output_note(&mut rng, input.get_nf().unwrap()))
            .collect::<Vec<_>>();
        let encoded_puzzle = pallas::Base::random(&mut rng);
        let sudoku_app_vk = pallas::Base::random(&mut rng);
        output_notes[0].note_type.app_data_static =
            DealerIntentValidityPredicateCircuit::compute_app_data_static(
                encoded_puzzle,
                sudoku_app_vk,
            );
        let encoded_solution = pallas::Base::random(&mut rng);
        let owned_note_pub_id = output_notes[0].commitment().inner();
        DealerIntentValidityPredicateCircuit {
            owned_note_pub_id,
            input_notes,
            output_notes: output_notes.try_into().unwrap(),
            encoded_puzzle,
            sudoku_app_vk,
            encoded_solution,
        }
    };
    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover =
        MockProver::<pallas::Base>::run(12, &circuit, vec![public_inputs.to_vec().clone()])
            .unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let params = SETUP_PARAMS_MAP.get(&12).unwrap();
    let vk = keygen_vk(params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(params, vk.clone(), &circuit).expect("keygen_pk should not fail");
    let proof = Proof::create(&pk, params, circuit, &[public_inputs.inner()], &mut rng).unwrap();

    proof.verify(&vk, params, &[public_inputs.inner()]).unwrap();
}
