use ff::PrimeField;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{floor_planner, AssignedCell, Chip, Layouter, Region},
    plonk::{Advice, Any, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;
use std::{convert::TryInto, marker::PhantomData};

// Blake2s constants
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// The SIGMA constant in Blake2s is a 10x16 array that defines the message permutations in the algorithm. Each of the 10 rows corresponds to a round of the hashing process, and each of the 16 elements in the row determines the message block order.
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[derive(Clone, Debug)]
pub struct Blake2sChip<F: Field> {
    config: Blake2sConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sConfig {
    pub v: [Column<Advice>; 4], // Advice columns used for the state and message block
    pub u: Column<Fixed>,       // Fixed column used for constants and other fixed values
    pub s_add: Selector,
    pub s_xor: Selector,
    pub s_rotate: Selector,
    pub s_shift_right: Selector,
}
// pub struct Blake2sConfig {
//     // Message block columns
//     message: [Column<Advice>; 4],

//     // Internal state columns
//     v: [Column<Advice>; 4],

//     // Working value columns
//     t: [Column<Advice>; 2],

//     // Constant columns
//     constants: Column<Advice>,

//     // Permutation columns
//     sigma: Column<Advice>,

//     // Selector columns for the S-box
//     sbox: [Selector; 16],

//     // Selector columns for controlling the message schedule and compression function
//     round: Selector,
//     message_schedule: Selector,
// }

impl Blake2sConfig {
    pub fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Blake2sConfig {
        let v0 = meta.advice_column();
        let v1 = meta.advice_column();
        let v2 = meta.advice_column();
        let v3 = meta.advice_column();

        let u = meta.fixed_column();
        let s_add = meta.selector();
        let s_xor = meta.selector();
        let s_rotate = meta.selector();
        let s_shift_right = meta.selector();

        // Define our addition gate!
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(v0, Rotation::cur());
            let rhs = meta.query_advice(v1, Rotation::cur());
            let out = meta.query_advice(v2, Rotation::cur());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (lhs + rhs - out)]
        });

        meta.create_gate("xor", |meta| {
            let lhs = meta.query_advice(v0, Rotation::cur());
            let rhs = meta.query_advice(v1, Rotation::cur());
            let out = meta.query_advice(v2, Rotation::cur());
            let s_xor = meta.query_selector(s_xor);

            vec![s_xor * (lhs.clone() + rhs.clone() - lhs * rhs - out)]
        });

        meta.create_gate("Shift right", |meta| {
            let lhs = meta.query_advice(v0, Rotation::cur());
            let shift = meta.query_fixed(u);
            let out = meta.query_advice(v1, Rotation::cur());
            let s_shift_right = meta.query_selector(s_shift_right);

            vec![s_shift_right * (lhs * shift - out)]
        });

        meta.create_gate("Rotation", |meta| {
            let lhs = meta.query_advice(v0, Rotation::cur());
            let rotation = meta.query_fixed(u);
            let out = meta.query_advice(v1, Rotation::cur());
            let s_rotate = meta.query_selector(s_rotate);

            vec![s_rotate * (lhs * rotation - out)]
        });

        Blake2sConfig {
            v: [v0, v1, v2, v3],
            u,
            s_add,
            s_xor,
            s_rotate,
            s_shift_right,
        }
    }
}

impl<F: Field> Chip<F> for Blake2sChip<F> {
    type Config = Blake2sConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> Blake2sChip<F> {
    pub fn construct(config: Blake2sConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn xor(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        y: &AssignedCell<pallas::Base, pallas::Base>,
        region: &mut Region<'_, pallas::Base>,
        config: &Blake2sConfig,
        offset: usize,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        let result_val = x
            .value()
            .zip(y.value())
            .map(|(x_val, y_val)| x_val + y_val - x_val * y_val);
        let result_cell =
            region.assign_advice(|| "xor", config.v[offset % 4], offset, || result_val)?;

        region.constrain_equal(x.cell(), result_cell.cell())?;
        region.constrain_equal(y.cell(), result_cell.cell())?;

        Ok(result_cell)
    }

    fn add(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        y: &AssignedCell<pallas::Base, pallas::Base>,
        region: &mut Region<'_, pallas::Base>,
        config: &Blake2sConfig,
        offset: usize,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        let result_val = x.value().zip(y.value()).map(|(x_val, y_val)| x_val + y_val);
        let result_cell =
            region.assign_advice(|| "add", config.v[offset % 4], offset, || result_val)?;

        region.constrain_equal(x.cell(), result_cell.cell())?;
        region.constrain_equal(y.cell(), result_cell.cell())?;

        Ok(result_cell)
    }

    fn rotate(
        &self,
        cell: &AssignedCell<pallas::Base, pallas::Base>,
        region: &mut Region<'_, pallas::Base>,
        config: &Blake2sConfig,
        rotation: i32,
        offset: usize,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        let rotated_value = cell.value().map(|v| {
            let pow_2: pallas::Base =
                pallas::Base::from(1u64 << (rotation as u64 % pallas::Base::NUM_BITS as u64));
            (v * pow_2) // % pallas::Base::MODULUS
        });
        let rotated_cell = region.assign_advice(
            || format!("rotate {}", rotation),
            config.v[offset % 4],
            offset,
            || rotated_value,
        )?;

        // Enforce the rotation constraint
        region.constrain_equal(cell.cell(), rotated_cell.cell())?;

        Ok(rotated_cell)
    }

    fn shift_right(
        &self,
        cell: &AssignedCell<pallas::Base, pallas::Base>,
        region: &mut Region<'_, pallas::Base>,
        config: &Blake2sConfig,
        shift: u32,
        offset: usize,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        let divisor = pallas::Base::from(1u64 << shift);

        let shifted_value = cell
            .value()
            .map(|v| *v * divisor.invert().unwrap_or(pallas::Base::zero()));
        let shifted_cell = region.assign_advice(
            || format!("shift right {}", shift),
            config.v[offset % 4],
            offset,
            || shifted_value,
        )?;

        // Enforce the shift constraint
        region.constrain_equal(cell.cell(), shifted_cell.cell())?;

        Ok(shifted_cell)
    }

    fn g(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 8],
        message: [AssignedCell<pallas::Base, pallas::Base>; 2],
        round: usize,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 8], Error> {
        // Implement the G function
        layouter.assign_region(
            || "G function",
            |mut region| {
                // First mixing stage
                let a = self.add(&state[0], &state[4], &mut region, &self.config, round % 4)?;
                let a = self.add(&a, &message[0], &mut region, &self.config, round % 4)?;

                let d = self.xor(&state[3], &a, &mut region, &self.config, round % 4)?;
                let d = self.rotate(&d, &mut region, &self.config, -16, round % 4)?;

                let c = self.add(&state[2], &d, &mut region, &self.config, round % 4)?;

                let b = self.xor(&state[1], &c, &mut region, &self.config, round % 4)?;
                let b = self.rotate(&b, &mut region, &self.config, -12, round % 4)?;

                // Second mixing stage
                let a = self.add(&a, &b, &mut region, &self.config, round % 4)?;
                let a = self.add(&a, &message[1], &mut region, &self.config, round % 4)?;

                let d = self.xor(&d, &a, &mut region, &self.config, round % 4)?;
                let d = self.rotate(&d, &mut region, &self.config, -8, round % 4)?;

                let c = self.add(&c, &d, &mut region, &self.config, round % 4)?;

                let b = self.xor(&b, &c, &mut region, &self.config, round % 4)?;
                let b = self.rotate(&b, &mut region, &self.config, -7, round % 4)?;

                Ok([
                    a,
                    b,
                    c,
                    d,
                    state[4].clone(),
                    state[5].clone(),
                    state[6].clone(),
                    state[7].clone(),
                ])
            },
        )
    }

    fn message_schedule(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        message_block: [AssignedCell<pallas::Base, pallas::Base>; 16],
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 16], Error> {
        // Implement the message schedule
        let mut message_schedule = Vec::with_capacity(64);

        // Copy the first 16 words of the message block into the message schedule
        for i in 0..16 {
            message_schedule.push(message_block[i].clone());
        }

        // Compute the remaining 48 words of the message schedule
        layouter.assign_region(
            || "message schedule",
            |mut region| {
                for i in 16..64 {
                    let s0 = self.xor(
                        &self.rotate(
                            &message_schedule[i - 15],
                            &mut region,
                            &self.config,
                            -7,
                            i % 4,
                        )?,
                        &self.rotate(
                            &message_schedule[i - 15],
                            &mut region,
                            &self.config,
                            -18,
                            i % 4,
                        )?,
                        &mut region,
                        &self.config,
                        i % 4,
                    )?;
                    let s0 = self.xor(
                        &s0,
                        &self.shift_right(
                            &message_schedule[i - 15],
                            &mut region,
                            &self.config,
                            3,
                            i % 4,
                        )?,
                        &mut region,
                        &self.config,
                        i % 4,
                    )?;

                    let s1 = self.xor(
                        &self.rotate(
                            &message_schedule[i - 2],
                            &mut region,
                            &self.config,
                            -17,
                            i % 4,
                        )?,
                        &self.rotate(
                            &message_schedule[i - 2],
                            &mut region,
                            &self.config,
                            -19,
                            i % 4,
                        )?,
                        &mut region,
                        &self.config,
                        i % 4,
                    )?;
                    let s1 = self.xor(
                        &s1,
                        &self.shift_right(
                            &message_schedule[i - 2],
                            &mut region,
                            &self.config,
                            10,
                            i % 4,
                        )?,
                        &mut region,
                        &self.config,
                        i % 4,
                    )?;

                    let sum = self.add(
                        &message_schedule[i - 16],
                        &s0,
                        &mut region,
                        &self.config,
                        i % 4,
                    )?;
                    let new_word = self.add(
                        &sum,
                        &message_schedule[i - 7],
                        &mut region,
                        &self.config,
                        i % 4,
                    )?;
                    let new_word = self.add(&new_word, &s1, &mut region, &self.config, i % 4)?;

                    message_schedule.push(new_word);
                }

                Ok(())
            },
        )?;

        // Create an array with the first 16 words of the updated message schedule
        Ok([
            message_schedule[0].clone(),
            message_schedule[1].clone(),
            message_schedule[2].clone(),
            message_schedule[3].clone(),
            message_schedule[4].clone(),
            message_schedule[5].clone(),
            message_schedule[6].clone(),
            message_schedule[7].clone(),
            message_schedule[8].clone(),
            message_schedule[9].clone(),
            message_schedule[10].clone(),
            message_schedule[11].clone(),
            message_schedule[12].clone(),
            message_schedule[13].clone(),
            message_schedule[14].clone(),
            message_schedule[15].clone(),
        ])
    }

    fn compression_function(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 8],
        message_block: [AssignedCell<pallas::Base, pallas::Base>; 16],
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 8], Error> {
        // 1. Compute the message schedule
        let message_schedule = self.message_schedule(layouter, message_block)?;

        // 2. Perform the 10 rounds of the Blake2s compression function
        let mut current_state = state.clone();
        for round in 0..10 {
            for g_index in 0..8 {
                let idx = SIGMA[round][2 * g_index];
                let idx1 = SIGMA[round][2 * g_index + 1];

                current_state = self.g(
                    layouter,
                    current_state,
                    [
                        message_schedule[idx as usize].clone(),
                        message_schedule[idx1 as usize].clone(),
                    ],
                    round,
                )?;
            }
        }

        // 3. Finalize the state
        let final_state = layouter.assign_region(
            || "Finalize state",
            |mut region| {
                let mut final_state = Vec::with_capacity(8);
                for i in 0..8 {
                    final_state.push(self.add(
                        &state[i],
                        &current_state[i],
                        &mut region,
                        &self.config,
                        i % 4,
                    )?);
                }
                Ok([
                    final_state[0].clone(),
                    final_state[1].clone(),
                    final_state[2].clone(),
                    final_state[3].clone(),
                    final_state[4].clone(),
                    final_state[5].clone(),
                    final_state[6].clone(),
                    final_state[7].clone(),
                ])
            },
        )?;

        Ok(final_state)
    }
}

#[derive(Clone, Debug, Default)]
pub struct TestCircuit {
    pub state: [pallas::Base; 8],
    pub message_block: [pallas::Base; 16],
    pub expected_output: [pallas::Base; 8],
}

impl Circuit<pallas::Base> for TestCircuit {
    type Config = Blake2sConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        Blake2sConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Instantiate the Blake2sChip
        let blake2s_chip = Blake2sChip::<pallas::Base>::construct(config);

        // Assign the initial state and message block
        let state: Vec<AssignedCell<pallas::Base, pallas::Base>> = layouter.assign_region(
            || "assign state",
            |mut region| {
                let mut state_cells = Vec::new();
                for (idx, value) in self.state.iter().enumerate() {
                    let cell = region.assign_advice_from_constant(
                        || "state",
                        config.v[idx % 4],
                        0,
                        *value,
                    )?;
                    state_cells.push(cell);
                }
                Ok(state_cells)
            },
        )?;

        let message_block: Vec<AssignedCell<pallas::Base, pallas::Base>> = layouter.assign_region(
            || "assign message block",
            |mut region| {
                let mut message_cells = Vec::new();
                for (idx, value) in self.message_block.iter().enumerate() {
                    let cell = region.assign_advice_from_constant(
                        || "message",
                        config.v[idx % 4],
                        0,
                        *value,
                    )?;
                    message_cells.push(cell);
                }
                Ok(message_cells)
            },
        )?;

        let state: [AssignedCell<pallas::Base, pallas::Base>; 8] = state.try_into().unwrap();
        let message_block: [AssignedCell<pallas::Base, pallas::Base>; 16] =
            message_block.try_into().unwrap();

        // Compress the message block
        let output_state =
            blake2s_chip.compression_function(&mut layouter, state, message_block)?;

        // TODO: Compare the output state to the expected output

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn array_map_u8_to_pallas_base(input: [u8; 16]) -> [pallas::Base; 16] {
        let mut result = [pallas::Base::zero(); 16];
        for (i, &val) in input.iter().enumerate() {
            result[i] = pallas::Base::from(val as u64);
        }
        result
    }

    fn array_map_u64_to_pallas_base(input: [u64; 8]) -> [pallas::Base; 8] {
        let mut result = [pallas::Base::zero(); 8];
        for (i, &val) in input.iter().enumerate() {
            result[i] = pallas::Base::from(val);
        }
        result
    }

    #[test]
    fn test_blake2s() {
        // Define the initial state and message block for the Blake2s hash operation.
        let state = [
            pallas::Base::from(0),
            pallas::Base::from(1),
            pallas::Base::from(2),
            pallas::Base::from(3),
            pallas::Base::from(4),
            pallas::Base::from(5),
            pallas::Base::from(6),
            pallas::Base::from(7),
        ];
        // Input message: "hello world"
        let message_block: [u8; 16] = [
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        // Convert the input message block to an array of pallas::Base.
        let message_block: [pallas::Base; 16] = array_map_u8_to_pallas_base(message_block);

        // Expected output hash: "2ef7bde608ce5404e97d5f042f95f89f1c2328712453612df0e2f3f71e3e5260"
        let expected_output: [u64; 8] = [
            0x2ef7bde6_08ce5404,
            0xe97d5f04_2f95f89f,
            0x1c232871_2453612d,
            0xf0e2f3f7_1e3e5260,
            0,
            0,
            0,
            0,
        ];

        // Convert the expected output to an array of pallas::Base.
        let expected_output: [pallas::Base; 8] = array_map_u64_to_pallas_base(expected_output);

        // Create an instance of the TestCircuit struct with the provided initial state and message block values.
        let circuit = TestCircuit {
            state,
            message_block,
            expected_output,
        };

        // Set the number of rows for the circuit.
        let n = 12;

        // Create a mock prover for the circuit.
        let mut prover = MockProver::<pallas::Base>::run(n, &circuit, vec![]).unwrap();

        // Verify the proof.
        let result = prover.verify();

        // Check if the proof is valid.
        assert!(result.is_ok(), "proof is invalid: {:?}", result.err());
    }
}
