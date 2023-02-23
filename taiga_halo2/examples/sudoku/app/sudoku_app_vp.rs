use ff::{Field, PrimeField};
use halo2_gadgets::{
    poseidon::{
        primitives as poseidon, primitives::ConstantLength, Hash as PoseidonHash,
        Pow5Chip as PoseidonChip,
    },
    utilities::bool_check,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner, AssignedCell, Layouter, Region, Value},
    plonk::{
        keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Constraints, Error,
        Expression, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;
use taiga_halo2::{
    circuit::{
        gadgets::{
            assign_free_advice, assign_free_constant,
            mul::{MulChip, MulConfig, MulInstructions},
            sub::{SubChip, SubConfig, SubInstructions},
            triple_mul::TripleMulConfig,
        },
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

use crate::app::gadgets::{
    state_check::SudokuStateCheckConfig, state_update::StateUpdateConfig,
    value_check::ValueCheckConfig,
};
#[derive(Clone, Debug)]
pub struct SudokuState {
    pub state: [[u8; 9]; 9],
}

impl SudokuState {
    pub fn encode(&self) -> pallas::Base {
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

impl Default for SudokuState {
    fn default() -> Self {
        SudokuState {
            state: [
                [7, 0, 9, 5, 3, 8, 1, 2, 4],
                [2, 0, 3, 7, 1, 9, 6, 5, 8],
                [8, 0, 1, 4, 6, 2, 9, 7, 3],
                [4, 0, 6, 9, 7, 5, 3, 1, 2],
                [5, 0, 7, 6, 2, 1, 4, 8, 9],
                [1, 0, 2, 8, 4, 3, 7, 6, 5],
                [6, 0, 8, 3, 5, 4, 2, 9, 7],
                [9, 0, 4, 2, 8, 6, 5, 3, 1],
                [3, 0, 5, 1, 9, 7, 8, 4, 6],
            ],
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SudokuAppValidityPredicateCircuit {
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // The note that vp owned is set at spend_notes[0] or output_notes[0] by default. Make it mandatory later.
    // is_spend_note helps locate the target note in spend_notes and output_notes.
    is_spend_note: pallas::Base,
    // Initial puzzle encoded in a single field
    encoded_init_state: pallas::Base,
    // If it is a init state, previous_state is equal to current_state
    previous_state: SudokuState,
    current_state: SudokuState,
}

#[derive(Clone, Debug)]
struct SudokuAppValidityPredicateConfig {
    note_config: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    // get_target_variable_config: GetTargetNoteVariableConfig,
    sudoku_state_check_config: SudokuStateCheckConfig,
    state_update_config: StateUpdateConfig,
    triple_mul_config: TripleMulConfig,
    value_check_config: ValueCheckConfig,
    sub_config: SubConfig,
    mul_config: MulConfig,
}

impl SudokuAppValidityPredicateConfig {
    pub fn sub_chip(&self) -> SubChip<pallas::Base> {
        SubChip::construct(self.sub_config.clone(), ())
    }

    pub fn mul_chip(&self) -> MulChip<pallas::Base> {
        MulChip::construct(self.mul_config.clone())
    }
}

impl ValidityPredicateConfig for SudokuAppValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_config.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_config = Self::configure_note(meta);

        let advices = note_config.advices;
        let instances = note_config.instances;
        let sudoku_state_check_config = SudokuStateCheckConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
            advices[6], advices[7],
        );
        let state_update_config =
            StateUpdateConfig::configure(meta, advices[0], advices[1], advices[2]);
        let triple_mul_config = TripleMulConfig::configure(meta, advices[0..3].try_into().unwrap());
        let value_check_config = ValueCheckConfig::configure(meta, advices[0], advices[1]);
        let sub_config = SubChip::configure(meta, [advices[0], advices[1]]);
        let mul_config = MulChip::configure(meta, [advices[0], advices[1]]);
        Self {
            note_config,
            advices,
            instances,
            sudoku_state_check_config,
            state_update_config,
            triple_mul_config,
            value_check_config,
            sub_config,
            mul_config,
        }
    }
}

impl SudokuAppValidityPredicateCircuit {
    #![allow(dead_code)]
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let mut output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let is_spend_note = pallas::Base::zero();
        let encoded_init_state = SudokuState::default().encode();
        let previous_state = SudokuState::default();
        let current_state = SudokuState::default();
        output_notes[0].value_base.app_data =
            poseidon_hash(encoded_init_state, current_state.encode());
        output_notes[0].value = 1u64;
        Self {
            spend_notes,
            output_notes,
            is_spend_note,
            encoded_init_state,
            previous_state,
            current_state,
        }
    }

    // Copy from valid_puzzle/circuit.rs
    #[allow(clippy::too_many_arguments)]
    fn check_puzzle(
        mut layouter: impl Layouter<pallas::Base>,
        config: &SudokuAppValidityPredicateConfig,
        // advice: Column<Advice>,
        state: &[AssignedCell<pallas::Base, pallas::Base>],
    ) -> Result<(), Error> {
        let non_zero_sudoku_cells: Vec<AssignedCell<pallas::Base, pallas::Base>> = state
            .iter()
            .enumerate()
            .map(|(i, x)| {
                // TODO: fix it, add constraints for non_zero_sudoku_cells assignment
                let ret = x.value().map(|x| {
                    if *x == pallas::Base::zero() {
                        pallas::Base::from_u128(10 + i as u128)
                    } else {
                        *x
                    }
                });
                assign_free_advice(layouter.namespace(|| "sudoku_cell"), config.advices[0], ret)
                    .unwrap()
            })
            .collect();

        // rows
        let rows: Vec<Vec<AssignedCell<pallas::Base, pallas::Base>>> = non_zero_sudoku_cells
            .chunks(9)
            .map(|row| row.to_vec())
            .collect();
        // cols
        let cols: Vec<Vec<AssignedCell<pallas::Base, pallas::Base>>> = (1..10)
            .map(|i| {
                let col: Vec<AssignedCell<pallas::Base, pallas::Base>> = non_zero_sudoku_cells
                    .chunks(9)
                    .map(|row| row[i - 1].clone())
                    .collect();
                col
            })
            .collect();
        // small squares
        let mut squares: Vec<Vec<AssignedCell<pallas::Base, pallas::Base>>> = vec![];
        for i in 1..4 {
            for j in 1..4 {
                let sub_lines = &rows[(i - 1) * 3..i * 3];

                let square: Vec<&[AssignedCell<pallas::Base, pallas::Base>]> = sub_lines
                    .iter()
                    .map(|line| &line[(j - 1) * 3..j * 3])
                    .collect();
                squares.push(square.concat());
            }
        }

        for perm in [rows, cols, squares].concat().iter() {
            let mut cell_lhs = assign_free_advice(
                layouter.namespace(|| "lhs init"),
                config.advices[0],
                Value::known(pallas::Base::one()),
            )
            .unwrap();
            for i in 0..9 {
                for j in (i + 1)..9 {
                    let diff = SubInstructions::sub(
                        &config.sub_chip(),
                        layouter.namespace(|| "diff"),
                        &perm[i],
                        &perm[j],
                    )
                    .unwrap();
                    cell_lhs = MulInstructions::mul(
                        &config.mul_chip(),
                        layouter.namespace(|| "lhs * diff"),
                        &cell_lhs,
                        &diff,
                    )
                    .unwrap();
                }
            }
            let cell_lhs_inv = assign_free_advice(
                layouter.namespace(|| "non-zero sudoku_cell"),
                config.advices[0],
                cell_lhs.value().map(|x| x.invert().unwrap()),
            )
            .unwrap();

            let cell_div = MulInstructions::mul(
                &config.mul_chip(),
                layouter.namespace(|| "lhs * 1/lhs"),
                &cell_lhs,
                &cell_lhs_inv,
            )
            .unwrap();

            let constant_one = assign_free_constant(
                layouter.namespace(|| "constant one"),
                config.advices[0],
                pallas::Base::one(),
            )?;

            layouter.assign_region(
                || "lhs * 1/lhs = 1",
                |mut region| region.constrain_equal(cell_div.cell(), constant_one.cell()),
            )?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn check_state(
        config: &SudokuStateCheckConfig,
        mut layouter: impl Layouter<pallas::Base>,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        init_state: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_pre_state: &AssignedCell<pallas::Base, pallas::Base>,
        output_note_cur_state: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_app_data_encode: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note: &SpendNoteVar,
        output_note: &OutputNoteVar,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "dealer intent check",
            |mut region| {
                config.assign_region(
                    is_spend_note,
                    init_state,
                    &spend_note.app_data,
                    spend_note_app_data_encode,
                    &spend_note.app_vk,
                    &output_note.app_vk,
                    spend_note_pre_state,
                    output_note_cur_state,
                    0,
                    &mut region,
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn check_solution(
        mut layouter: impl Layouter<pallas::Base>,
        state_update_config: &StateUpdateConfig,
        triple_mul_config: &TripleMulConfig,
        value_check_config: &ValueCheckConfig,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        pre_state: &[AssignedCell<pallas::Base, pallas::Base>],
        cur_state: &[AssignedCell<pallas::Base, pallas::Base>],
        _spend_note: &SpendNoteVar,
        output_note: &OutputNoteVar,
    ) -> Result<(), Error> {
        // check state update: the cur_state is updated from pre_state
        pre_state
            .iter()
            .zip(cur_state.iter())
            .for_each(|(pre_state_cell, cur_state_cell)| {
                layouter
                    .assign_region(
                        || "state update check",
                        |mut region| {
                            state_update_config.assign_region(
                                is_spend_note,
                                pre_state_cell,
                                cur_state_cell,
                                0,
                                &mut region,
                            )
                        },
                    )
                    .unwrap();
            });

        // if cur_state is the final solution, check the output.value is zero else check the output.value is one
        // ret has 27 elements
        let ret: Vec<AssignedCell<pallas::Base, pallas::Base>> = cur_state
            .chunks(3)
            .map(|triple| {
                layouter
                    .assign_region(
                        || "triple mul",
                        |mut region| {
                            triple_mul_config.assign_region(
                                &triple[0],
                                &triple[1],
                                &triple[2],
                                0,
                                &mut region,
                            )
                        },
                    )
                    .unwrap()
            })
            .collect();
        // ret has 9 elements
        let ret: Vec<AssignedCell<pallas::Base, pallas::Base>> = ret
            .chunks(3)
            .map(|triple| {
                layouter
                    .assign_region(
                        || "triple mul",
                        |mut region| {
                            triple_mul_config.assign_region(
                                &triple[0],
                                &triple[1],
                                &triple[2],
                                0,
                                &mut region,
                            )
                        },
                    )
                    .unwrap()
            })
            .collect();
        // ret has 3 elements
        let ret: Vec<AssignedCell<pallas::Base, pallas::Base>> = ret
            .chunks(3)
            .map(|triple| {
                layouter
                    .assign_region(
                        || "triple mul",
                        |mut region| {
                            triple_mul_config.assign_region(
                                &triple[0],
                                &triple[1],
                                &triple[2],
                                0,
                                &mut region,
                            )
                        },
                    )
                    .unwrap()
            })
            .collect();
        let product = layouter.assign_region(
            || "triple mul",
            |mut region| triple_mul_config.assign_region(&ret[0], &ret[1], &ret[2], 0, &mut region),
        )?;

        layouter.assign_region(
            || "check value",
            |mut region| {
                value_check_config.assign_region(&product, &output_note.value, 0, &mut region)
            },
        )?;

        Ok(())
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
        let previous_sudoku_cells: Vec<AssignedCell<_, _>> = self
            .previous_state
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
        let current_sudoku_cells: Vec<AssignedCell<_, _>> = self
            .current_state
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

        // TODO: constrain the encoding of states instead of witnessing them.
        let encoded_previous_state = assign_free_advice(
            layouter.namespace(|| "witness encoded_previous_state"),
            config.advices[0],
            Value::known(self.previous_state.encode()),
        )?;

        let encoded_current_state = assign_free_advice(
            layouter.namespace(|| "witness encoded_current_state"),
            config.advices[0],
            Value::known(self.current_state.encode()),
        )?;

        // app_data = poseidon_hash(encoded_init_state || encoded_state)
        let encoded_init_state = assign_free_advice(
            layouter.namespace(|| "witness encoded_init_state"),
            config.advices[0],
            Value::known(self.encoded_init_state),
        )?;
        let spend_note_app_data_encode = {
            let poseidon_config = config.get_note_config().poseidon_config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [encoded_init_state.clone(), encoded_previous_state.clone()];
            poseidon_hasher.hash(
                layouter.namespace(|| "get spend note app_data encoding"),
                poseidon_message,
            )?
        };
        let output_note_app_data_encode = {
            let poseidon_config = config.get_note_config().poseidon_config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [encoded_init_state.clone(), encoded_current_state.clone()];
            poseidon_hasher.hash(
                layouter.namespace(|| "get output note app_data encoding"),
                poseidon_message,
            )?
        };

        layouter.assign_region(
            || "check output note app_data encoding",
            |mut region| {
                region.constrain_equal(
                    output_note_app_data_encode.cell(),
                    output_note_variables[0].app_data.cell(),
                )
            },
        )?;

        Self::check_puzzle(
            layouter.namespace(|| "check puzzle"),
            &config,
            &current_sudoku_cells,
        )?;

        // check state
        Self::check_state(
            &config.sudoku_state_check_config,
            layouter.namespace(|| "check state"),
            &is_spend_note,
            &encoded_init_state,
            &encoded_previous_state,
            &encoded_current_state,
            &spend_note_app_data_encode,
            &spend_note_variables[0],
            &output_note_variables[0],
        )?;

        // if it is a spend note, check that the cur_state is updated from pre_state
        // if encoded_current_state is the final solution, check the output.value is zero else check the output.value is one
        Self::check_solution(
            layouter.namespace(|| "check solution"),
            &config.state_update_config,
            &config.triple_mul_config,
            &config.value_check_config,
            &is_spend_note,
            &previous_sudoku_cells,
            &current_sudoku_cells,
            &spend_note_variables[0],
            &output_note_variables[0],
        )?;

        Ok(())
    }
}

vp_circuit_impl!(SudokuAppValidityPredicateCircuit);

#[test]
fn test_halo2_sudoku_app_vp_circuit_init() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = SudokuAppValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(13, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_halo2_sudoku_app_vp_circuit_update() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    // Construct circuit
    let circuit = {
        let mut spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let mut output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let is_spend_note = pallas::Base::one();
        let init_state = SudokuState {
            state: [
                [5, 0, 1, 6, 7, 2, 4, 3, 9],
                [7, 0, 2, 8, 4, 3, 6, 5, 1],
                [3, 0, 4, 5, 9, 1, 7, 8, 2],
                [4, 0, 8, 9, 5, 7, 2, 1, 6],
                [2, 0, 6, 1, 8, 4, 9, 7, 3],
                [1, 0, 9, 3, 2, 6, 8, 4, 5],
                [8, 0, 5, 2, 1, 9, 3, 6, 7],
                [9, 0, 3, 7, 6, 8, 5, 2, 4],
                [6, 0, 7, 4, 3, 5, 1, 9, 8],
            ],
        };
        let encoded_init_state = init_state.encode();
        let previous_state = SudokuState {
            state: [
                [5, 8, 1, 6, 7, 2, 4, 3, 9],
                [7, 9, 2, 8, 4, 3, 6, 5, 1],
                [3, 0, 4, 5, 9, 1, 7, 8, 2],
                [4, 0, 8, 9, 5, 7, 2, 1, 6],
                [2, 0, 6, 1, 8, 4, 9, 7, 3],
                [1, 0, 9, 3, 2, 6, 8, 4, 5],
                [8, 0, 5, 2, 1, 9, 3, 6, 7],
                [9, 0, 3, 7, 6, 8, 5, 2, 4],
                [6, 0, 7, 4, 3, 5, 1, 9, 8],
            ],
        };
        let current_state = SudokuState {
            state: [
                [5, 8, 1, 6, 7, 2, 4, 3, 9],
                [7, 9, 2, 8, 4, 3, 6, 5, 1],
                [3, 6, 4, 5, 9, 1, 7, 8, 2],
                [4, 3, 8, 9, 5, 7, 2, 1, 6],
                [2, 0, 6, 1, 8, 4, 9, 7, 3],
                [1, 0, 9, 3, 2, 6, 8, 4, 5],
                [8, 0, 5, 2, 1, 9, 3, 6, 7],
                [9, 0, 3, 7, 6, 8, 5, 2, 4],
                [6, 0, 7, 4, 3, 5, 1, 9, 8],
            ],
        };
        spend_notes[0].value_base.app_data =
            poseidon_hash(encoded_init_state, previous_state.encode());
        spend_notes[0].value = 1u64;
        output_notes[0].value_base.app_data =
            poseidon_hash(encoded_init_state, current_state.encode());
        output_notes[0].value = 1u64;
        output_notes[0].value_base.app_vk = spend_notes[0].value_base.app_vk.clone();
        SudokuAppValidityPredicateCircuit {
            spend_notes,
            output_notes,
            is_spend_note,
            encoded_init_state,
            previous_state,
            current_state,
        }
    };
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(13, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_halo2_sudoku_app_vp_circuit_final() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    // Construct circuit
    let circuit = {
        let mut spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let mut output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let is_spend_note = pallas::Base::one();
        let init_state = SudokuState {
            state: [
                [5, 0, 1, 6, 7, 2, 4, 3, 9],
                [7, 0, 2, 8, 4, 3, 6, 5, 1],
                [3, 0, 4, 5, 9, 1, 7, 8, 2],
                [4, 0, 8, 9, 5, 7, 2, 1, 6],
                [2, 0, 6, 1, 8, 4, 9, 7, 3],
                [1, 0, 9, 3, 2, 6, 8, 4, 5],
                [8, 0, 5, 2, 1, 9, 3, 6, 7],
                [9, 0, 3, 7, 6, 8, 5, 2, 4],
                [6, 0, 7, 4, 3, 5, 1, 9, 8],
            ],
        };
        let encoded_init_state = init_state.encode();
        let previous_state = SudokuState {
            state: [
                [5, 8, 1, 6, 7, 2, 4, 3, 9],
                [7, 9, 2, 8, 4, 3, 6, 5, 1],
                [3, 0, 4, 5, 9, 1, 7, 8, 2],
                [4, 0, 8, 9, 5, 7, 2, 1, 6],
                [2, 0, 6, 1, 8, 4, 9, 7, 3],
                [1, 0, 9, 3, 2, 6, 8, 4, 5],
                [8, 0, 5, 2, 1, 9, 3, 6, 7],
                [9, 0, 3, 7, 6, 8, 5, 2, 4],
                [6, 0, 7, 4, 3, 5, 1, 9, 8],
            ],
        };
        let current_state = SudokuState {
            state: [
                [5, 8, 1, 6, 7, 2, 4, 3, 9],
                [7, 9, 2, 8, 4, 3, 6, 5, 1],
                [3, 6, 4, 5, 9, 1, 7, 8, 2],
                [4, 3, 8, 9, 5, 7, 2, 1, 6],
                [2, 5, 6, 1, 8, 4, 9, 7, 3],
                [1, 7, 9, 3, 2, 6, 8, 4, 5],
                [8, 4, 5, 2, 1, 9, 3, 6, 7],
                [9, 1, 3, 7, 6, 8, 5, 2, 4],
                [6, 2, 7, 4, 3, 5, 1, 9, 8],
            ],
        };
        spend_notes[0].value_base.app_data =
            poseidon_hash(encoded_init_state, previous_state.encode());
        spend_notes[0].value = 1u64;
        output_notes[0].value_base.app_data =
            poseidon_hash(encoded_init_state, current_state.encode());
        output_notes[0].value = 0u64;
        output_notes[0].value_base.app_vk = spend_notes[0].value_base.app_vk.clone();
        SudokuAppValidityPredicateCircuit {
            spend_notes,
            output_notes,
            is_spend_note,
            encoded_init_state,
            previous_state,
            current_state,
        }
    };
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(13, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
