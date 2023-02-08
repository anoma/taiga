use ff::PrimeField;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner, AssignedCell, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;
use taiga_halo2::{
    circuit::{
        gadgets::{assign_free_advice, GetTargetNoteVariableConfig},
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
pub struct SudokuState {
    pub state: [[u8; 9]; 9],
}

impl SudokuState {
    pub fn encode_to_app_data(&self) -> pallas::Base {
        // TODO: add the rho of note to make the app_data unique.

        let sudoku = self.state.concat();
        let s1 = &sudoku[..sudoku.len() / 2]; // s1 contains 40 elements
        let s2 = &sudoku[sudoku.len() / 2..]; // s2 contains 41 elements
        let u: Vec<u8> = s1
            .iter()
            .zip(s2.iter()) // zip contains 40 elements
            .map(|(b1, b2)| {
                // Two entries of the sudoku can be seen as [b0,b1,b2,b3] and [c0,c1,c2,c3]
                // We store [b0,b1,b2,b3,c0,c1,c2,c3] here.
                assert!(b1 + 16 * b2 < 255);
                b1 + 16 * b2
            })
            .chain(s2.last().copied()) // there's 41st element in s2, so we add it here
            .collect();

        // fill u with zeros.
        // The length of u is 41 bytes, or 328 bits, since we are allocating 4 bits
        // per the first 40 integers and let the last sudoku digit takes an entire byte.
        // We still need to add 184 bits (i.e. 23 bytes) to reach 2*256=512 bits in total.
        // let u2 = [u, vec![0; 23]].concat(); // this is not working with all puzzles
        // For some reason, not _any_ byte array can be transformed into a 256-bit field element.
        // Preliminary investigation shows that `pallas::Base::from_repr` fails on a 32 byte array
        // if the first bit of every 8-byte (== u64) chunk is set to '1'. For now, we just add a zero
        // byte every 7 bytes, which is not ideal but works. Further investigation is needed.
        let mut u2 = [0u8; 64];
        let mut i = 0;
        let mut j = 0;
        while j != u.len() {
            if (i + 1) % 8 != 0 {
                u2[i] = u[j];
                j += 1;
            }
            i += 1;
        }
        let u_first: [u8; 32] = u2[0..32].try_into().unwrap();
        let u_last: [u8; 32] = u2[32..].try_into().unwrap();

        let x = pallas::Base::from_repr(u_first).unwrap();
        let y = pallas::Base::from_repr(u_last).unwrap();
        poseidon_hash(x, y)
    }
}

#[derive(Clone, Debug, Default)]
struct SudokuAppValidityPredicateCircuit {
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // The note that vp owned is set at spend_notes[0] or output_notes[0] by default. Make it mandatory later.
    // is_spend_note helps locate the target note in spend_notes and output_notes.
    is_spend_note: pallas::Base,
    // The output note doesn't need the sudoku_previous_state, use a default SudokuState.
    sudoku_previous_state: SudokuState,
    sudoku_current_state: SudokuState,
}

#[derive(Clone, Debug)]
struct SudokuAppValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    get_target_variable_config: GetTargetNoteVariableConfig,
}

impl ValidityPredicateConfig for SudokuAppValidityPredicateConfig {
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

        Self {
            note_conifg,
            advices,
            instances,
            get_target_variable_config,
        }
    }
}

impl SudokuAppValidityPredicateCircuit {
    #![allow(dead_code)]
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let mut spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let mut output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let is_spend_note = pallas::Base::zero();
        let sudoku_previous_state = SudokuState::default();
        let sudoku_current_state = SudokuState::default();
        // output_notes[0].value_base.app_data = sudoku_state.encode_to_app_data();
        // spend_notes[0].value_base.app_data = sudoku_state.encode_to_app_data();
        Self {
            spend_notes,
            output_notes,
            is_spend_note,
            sudoku_previous_state,
            sudoku_current_state,
        }
    }
}

impl ValidityPredicateInfo for SudokuAppValidityPredicateCircuit {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();

        instances.push(self.is_spend_note);

        // TODO: add dealer intent vp commitment

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

impl ValidityPredicateCircuit for SudokuAppValidityPredicateCircuit {
    type VPConfig = SudokuAppValidityPredicateConfig;
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

        // witness the sudoku previous state
        let _previous_sudoku_cells: Vec<AssignedCell<_, _>> = self
            .sudoku_previous_state
            .state
            .concat()
            .iter()
            .map(|x| {
                assign_free_advice(
                    layouter.namespace(|| "sudoku_cell"),
                    config.advices[0],
                    Value::known(pallas::Base::from_u128(*x as u128)),
                )
                .unwrap()
            })
            .collect();

        // witness the sudoku current state
        let _current_sudoku_cells: Vec<AssignedCell<_, _>> = self
            .sudoku_current_state
            .state
            .concat()
            .iter()
            .map(|x| {
                assign_free_advice(
                    layouter.namespace(|| "sudoku_cell"),
                    config.advices[0],
                    Value::known(pallas::Base::from_u128(*x as u128)),
                )
                .unwrap()
            })
            .collect();

        // if it is a spend note, decode and check the state transition
        // if it is a output note, do nothing
        check_state_transition()?;

        Ok(())
    }
}

vp_circuit_impl!(SudokuAppValidityPredicateCircuit);

// TODO: add state transition constraints
fn check_state_transition(// is_spend_note:
    // previous_state:
    // current_state:
    // spend_note:
    // output_note:
) -> Result<(), Error> {
    // output note app_data decoding

    // if is_spend_note is true, input note app_data decoding and check the validity of state transition

    Ok(())
}

#[test]
fn test_halo2_dealer_intent_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = SudokuAppValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
