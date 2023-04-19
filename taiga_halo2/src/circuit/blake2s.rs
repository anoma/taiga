use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Selector},
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
pub struct Blake2sChip<F: FieldExt> {
    config: Blake2sConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sConfig {
    // Message block columns
    message: [Column<Advice>; 4],

    // Internal state columns
    v: [Column<Advice>; 4],

    // Working value columns
    t: [Column<Advice>; 2],

    // Constant columns
    constants: Column<Advice>,

    // Permutation columns
    sigma: Column<Advice>,

    // Selector columns for the S-box
    sbox: [Selector; 16],

    // Selector columns for controlling the message schedule and compression function
    round: Selector,
    message_schedule: Selector,
}

impl<F: FieldExt> Chip<F> for Blake2sChip<F> {
    type Config = Blake2sConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> Blake2sChip<F> {
    pub fn construct(config: Blake2sConfig, _loaded: <Self as Chip<F>>::Loaded) -> Self {
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
        let result_cell = region.assign_advice(
            || "xor",
            config.v[offset % 4],
            offset,
            || result_val,
        )?;

        region.constrain_equal(x.cell(), result_cell.cell())?;
        region.constrain_equal(y.cell(), result_cell.cell())?;

        Ok(AssignedCell {
            cell: result_cell.cell(),
            value: result_val,
            _marker: PhantomData,
        })
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
        let result_cell = region.assign_advice(
            || "add",
            config.v[offset % 4],
            offset,
            || result_val,
        )?;

        region.constrain_equal(x.cell(), result_cell.cell())?;
        region.constrain_equal(y.cell(), result_cell.cell())?;

        Ok(AssignedCell {
            cell: result_cell.cell(),
            value: result_val,
            _marker: PhantomData,
        })
    }

    fn g(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 8],
        message: [AssignedCell<pallas::Base, pallas::Base>; 4],
        round: usize,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 8], Error> {
        // Implement the G function
        let (idx_a, idx_b, idx_c, idx_d) = (0, 1, 2, 3);
        let (mut a, mut b, mut c, mut d) = (state[idx_a], state[idx_b], state[idx_c], state[idx_d]);

        // First mixing stage
        layouter.assign_region(
            || "G function first mixing stage",
            |mut region| {
                a = self.add(&a, &b, &mut region, &self.config, 0)?;
                d = self.xor(&d, &c, &mut region, &self.config, 0)?;
                // .rotate(
                //     &mut region,
                //     &self.config,
                //     -16,
                // )?;
                c = self.add(&c, &d, &mut region, &self.config, 1)?;
                b = self.xor(&b, &a, &mut region, &self.config, 1)?;
                // .rotate(
                //     &mut region,
                //     &self.config,
                //     -12,
                // )?;

                Ok(())
            },
        )?;

        // Second mixing stage
        layouter.assign_region(
            || "G function second mixing stage",
            |mut region| {
                let message_idx = SIGMA[round][2 * idx_a] as usize;
                a = self.add(&a, &message[message_idx], &mut region, &self.config, 2)?;
                a = self.add(&a, &b, &mut region, &self.config, 2)?;
                d = self.xor(&d, &c, &mut region, &self.config, 2)?;
                // .rotate(
                //     &mut region,
                //     &self.config,
                //     -8,
                // )?;
                c = self.add(&c, &d, &mut region, &self.config, 3)?;
                b = self.xor(&b, &a, &mut region, &self.config, 3)?;
                // .rotate(
                //     &mut region,
                //     &self.config,
                //     -7,
                // )?;

                Ok(())
            },
        )?;

        let new_state = [a, b, c, d, state[4], state[5], state[6], state[7]];

        Ok(new_state)
    }

    fn message_schedule(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        message_block: [AssignedCell<pallas::Base, pallas::Base>; 16],
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 16], Error> {
        // Implement the message schedule
    let mut message_schedule = [AssignedCell::default(); 16];

    // Copy the first 16 words of the message block into the message schedule
    for i in 0..16 {
        message_schedule[i] = message_block[i];
    }

    // Compute the remaining 48 words of the message schedule
    layouter.assign_region(
        || "message schedule",
        |mut region| {
            for i in 16..64 {
                let s0 = message_schedule[i - 15]
                    .clone()
                    .rotate(&mut region, &self.config, -7)?
                    .xor(&mut region, &self.config, &message_schedule[i - 15].rotate(&mut region, &self.config, -18)?)?
                    .xor(&mut region, &self.config, &message_schedule[i - 15].shift_right(&mut region, &self.config, 3)?)?;

                    let s1 = message_schedule[i - 2]
                    .clone()
                    .rotate(&mut region, &self.config, -17)?
                    .xor(&mut region, &self.config, &message_schedule[i - 2].rotate(&mut region, &self.config, -19)?)?
                    .xor(&mut region, &self.config, &message_schedule[i - 2].shift_right(&mut region, &self.config, 10)?)?;

                let sum = self.add(&message_schedule[i - 16], &s0, &mut region, &self.config, i % 4)?;
                let new_word = self.add(&sum, &message_schedule[i - 7], &mut region, &self.config, i % 4)?;
                let new_word = self.add(&new_word, &s1, &mut region, &self.config, i % 4)?;

                message_schedule[i] = new_word;
            }

            Ok(())
        },
    )?;

    Ok(message_schedule)
    }

    fn compression_function(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        initial_state: [AssignedCell<pallas::Base, pallas::Base>; 8],
        message_blocks: &[[AssignedCell<pallas::Base, pallas::Base>; 16]],
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 8], Error> {
        let mut state = initial_state;

        for (round_idx, message_block) in message_blocks.iter().enumerate() {
            // 1. Apply the message schedule
            let scheduled_message = self.message_schedule(layouter, *message_block)?;

            // 2. Execute the G function for each column
            for col_idx in 0..4 {
                let input_state = [
                    state[col_idx * 2],
                    state[col_idx * 2 + 1],
                    state[(col_idx * 2 + 2) % 8],
                    state[(col_idx * 2 + 3) % 8],
                ];

                state = self.g(layouter, input_state, scheduled_message, round_idx)?;
            }
            // 3. Finalize the state
            let mut final_state = [AssignedCell::default(); 8];
            for i in 0..8 {
                layouter.assign_region(
                    || "Finalize state",
                    |mut region| {
                        let row_offset = 0;

                        let lc_initial_state = region.assign_advice(
                            || format!("LC initial_state[{}]", i),
                            self.config.v[i % 4],
                            row_offset,
                            || initial_state[i].value(),
                        )?;

                        let lc_state = region.assign_advice(
                            || format!("LC state[{}]", i),
                            self.config.v[(i + 1) % 4],
                            row_offset,
                            || state[i].value(),
                        )?;

                        region.constrain_equal(initial_state[i].cell(), lc_initial_state.cell())?;
                        region.constrain_equal(state[i].cell(), lc_state.cell())?;

                        let final_val = Expression::from(lc_initial_state)
                            + Expression::from(lc_state.value())
                            - (Expression::from(initial_state[i].value())
                                * Expression::from(state[i].value()));

                        let final_cell = region.assign_advice(
                            || format!("final_state[{}]", i),
                            self.config.v[(i + 2) % 4],
                            row_offset,
                            || {
                                final_val.evaluate(
                                    &|_| pallas::Base::zero(),
                                    &|_| pallas::Base::zero(),
                                    &|_| pallas::Base::zero(),
                                    &|query| {
                                        if let Some(value) =
                                            region.get_assigned_value(query.column, query.at)
                                        {
                                            value
                                        } else {
                                            pallas::Base::zero()
                                        }
                                    },
                                    &|_| pallas::Base::zero(),
                                    &|value| -value,
                                    &|a, b| a + b,
                                    &|a, b| a * b,
                                    &|a, _| a,
                                )
                            },
                        )?;

                        final_state[i] = AssignedCell {
                            cell: final_cell,
                            value: region.get_assigned_value(final_cell),
                        };

                        Ok(())
                    },
                )?;
            }

            Ok(final_state)
        }
    }
}
// const BLOCK_SIZE: usize = 64; // block size in bytes
// const ROUND_COUNT: usize = 10; // number of rounds

// pub(crate) struct Blake2sCircuit {
//     message: [u8; BLOCK_SIZE],
// }

// pub(crate) struct Blake2sConfig {
//     message_column: Column<Advice>,
//     state_columns: [Column<Advice>; 8],
//     round_constants: Column<Fixed>,
//     sbox_selector: Selector,
// }

// impl Circuit<Fp> for Blake2sCircuit {
//     fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
//         // Define columns and selectors
//         // ... (implementation depends on the design of the circuit)

//         // Define constraints
//         // ... (implementation depends on the design of the circuit)
//     }

//     fn synthesize(
//         &self,
//         cs: &mut impl plonk::Assignment<Fp>,
//         config: Self::Config,
//     ) -> Result<(), Error> {
//         // Load the message into the circuit
//     }
// }
