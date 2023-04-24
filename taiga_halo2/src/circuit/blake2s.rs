use ff::PrimeField;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{floor_planner, AssignedCell, Chip, Layouter, Region},
    plonk::{Advice, Any, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;
use std::{convert::TryInto, marker::PhantomData};

//               | BLAKE2s          |
// --------------+------------------+
//  Bits in word | w = 32           |
//  Rounds in F  | r = 10           |
//  Block bytes  | bb = 64          |
//  Hash bytes   | 1 <= nn <= 32    |
//  Key bytes    | 0 <= kk <= 32    |
//  Input bytes  | 0 <= ll < 2**64  |
// --------------+------------------+
//  G Rotation   | (R1, R2, R3, R4) |
//   constants = | (16, 12,  8,  7) |
// --------------+------------------+

// BLAKE2 CONSTANTS
// ----------------

// Initialisation Vector (IV)
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

// G Rotation constants
const R1: u32 = 16;
const R2: u32 = 12;
const R3: u32 = 8;
const R4: u32 = 7;

// ---------------

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

impl Blake2sConfig {
    pub fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Blake2sConfig {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        let u = meta.fixed_column();
        let s_add = meta.selector();
        let s_xor = meta.selector();
        let s_rotate = meta.selector();
        let s_shift_right = meta.selector();

        // Define our addition gate
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advices[0], Rotation::cur());
            let rhs = meta.query_advice(advices[1], Rotation::cur());
            let out = meta.query_advice(advices[2], Rotation::cur());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (lhs + rhs - out)]
        });

        // Define our xor gate
        meta.create_gate("xor", |meta| {
            let lhs = meta.query_advice(advices[0], Rotation::cur());
            let rhs = meta.query_advice(advices[1], Rotation::cur());
            let out = meta.query_advice(advices[2], Rotation::cur());
            let s_xor = meta.query_selector(s_xor);

            vec![s_xor * (lhs.clone() + rhs.clone() - lhs * rhs - out)]
        });

        // Define our shift right gate
        meta.create_gate("Shift right", |meta| {
            let lhs = meta.query_advice(advices[0], Rotation::cur());
            let shift = meta.query_fixed(u);
            let out = meta.query_advice(advices[1], Rotation::cur());
            let s_shift_right = meta.query_selector(s_shift_right);

            vec![s_shift_right * (lhs * shift - out)]
        });

        // Define our rotation gate
        meta.create_gate("Rotation", |meta| {
            let lhs = meta.query_advice(advices[0], Rotation::cur());
            let rotation = meta.query_fixed(u);
            let out = meta.query_advice(advices[1], Rotation::cur());
            let s_rotate = meta.query_selector(s_rotate);

            vec![s_rotate * (lhs * rotation - out)]
        });

        Blake2sConfig {
            v: advices,
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

        Ok(result_cell)
    }

    // TODO: Add mod 2^32
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

        Ok(result_cell)
    }

    fn rotate_right(
        &self,
        cell: &AssignedCell<pallas::Base, pallas::Base>,
        region: &mut Region<'_, pallas::Base>,
        config: &Blake2sConfig,
        rotation: u32,
        offset: usize,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        let rotated_value = cell.value().map(|v| {
            let num_bits = pallas::Base::NUM_BITS;
            let k_mod_num_bits = rotation % num_bits;
            
            // Compute the right rotation factor
            let rotation_factor = pallas::Base::from(2).pow_vartime(&[(num_bits - k_mod_num_bits) as u64]);
            
            v * rotation_factor
        });
        let rotated_cell = region.assign_advice(
            || format!("rotate {}", rotation),
            config.v[offset % 4],
            offset,
            || rotated_value,
        )?;

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

    // The G primitive function mixes two input words, "x" and "y", into
    // four words indexed by "a", "b", "c", and "d" in the working vector
    // v[0..15].  The full modified vector is returned.  The rotation
    // constants
    // FUNCTION G( v[0..15], a, b, c, d, x, y )
    // |
    // |   v[a] := (v[a] + v[b] + x) mod 2**w
    // |   v[d] := (v[d] ^ v[a]) >>> R1
    // |   v[c] := (v[c] + v[d])     mod 2**w
    // |   v[b] := (v[b] ^ v[c]) >>> R2
    // |   v[a] := (v[a] + v[b] + y) mod 2**w
    // |   v[d] := (v[d] ^ v[a]) >>> R3
    // |   v[c] := (v[c] + v[d])     mod 2**w
    // |   v[b] := (v[b] ^ v[c]) >>> R4
    // |
    // |   RETURN v[0..15]
    // |
    // END FUNCTION.
    fn g(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 16],
        message: [AssignedCell<pallas::Base, pallas::Base>; 2],
        round: usize,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 16], Error> {
        layouter.assign_region(
            || "G function",
            |mut region| {
                let x = &message[0];
                let y = &message[1];
                let va = &state[0];
                let vb = &state[1];
                let vc = &state[2];
                let vd = &state[3];

                // First mixing stage
                let va = self.add(va, vb, &mut region, &self.config, round % 4)?;
                let va = self.add(&va, &x, &mut region, &self.config, round % 4)?;

                let vd = self.xor(vd, &va, &mut region, &self.config, round % 4)?;
                let vd = self.rotate_right(&vd, &mut region, &self.config, R1, round % 4)?;

                let vc = self.add(vc, &vd, &mut region, &self.config, round % 4)?;

                let vb = self.xor(&vb, &vc, &mut region, &self.config, round % 4)?;
                let vb = self.rotate_right(&vb, &mut region, &self.config, R2, round % 4)?;

                // Second mixing stage
                let va = self.add(&va, &vb, &mut region, &self.config, round % 4)?;
                let va = self.add(&va, &y, &mut region, &self.config, round % 4)?;

                let vd = self.xor(&vd, &va, &mut region, &self.config, round % 4)?;
                let vd = self.rotate_right(&vd, &mut region, &self.config, R3, round % 4)?;

                let vc = self.add(&vc, &vd, &mut region, &self.config, round % 4)?;

                let vb = self.xor(&vb, &vc, &mut region, &self.config, round % 4)?;
                let vb = self.rotate_right(&vb, &mut region, &self.config, R4, round % 4)?;

                Ok([
                    va,
                    vb,
                    vc,
                    vd,
                    state[4].clone(),
                    state[5].clone(),
                    state[6].clone(),
                    state[7].clone(),
                    state[8].clone(),
                    state[9].clone(),
                    state[10].clone(),
                    state[11].clone(),
                    state[12].clone(),
                    state[13].clone(),
                    state[14].clone(),
                    state[15].clone(),
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
        // layouter.assign_region(
        //     || "message schedule",
        //     |mut region| {
        //         for i in 16..64 {
        //             let s0 = self.xor(
        //                 &self.rotate(
        //                     &message_schedule[i - 15],
        //                     &mut region,
        //                     &self.config,
        //                     -7,
        //                     i % 4,
        //                 )?,
        //                 &self.rotate(
        //                     &message_schedule[i - 15],
        //                     &mut region,
        //                     &self.config,
        //                     -18,
        //                     i % 4,
        //                 )?,
        //                 &mut region,
        //                 &self.config,
        //                 i % 4,
        //             )?;
        //             let s0 = self.xor(
        //                 &s0,
        //                 &self.shift_right(
        //                     &message_schedule[i - 15],
        //                     &mut region,
        //                     &self.config,
        //                     3,
        //                     i % 4,
        //                 )?,
        //                 &mut region,
        //                 &self.config,
        //                 i % 4,
        //             )?;

        //             let s1 = self.xor(
        //                 &self.rotate(
        //                     &message_schedule[i - 2],
        //                     &mut region,
        //                     &self.config,
        //                     -17,
        //                     i % 4,
        //                 )?,
        //                 &self.rotate(
        //                     &message_schedule[i - 2],
        //                     &mut region,
        //                     &self.config,
        //                     -19,
        //                     i % 4,
        //                 )?,
        //                 &mut region,
        //                 &self.config,
        //                 i % 4,
        //             )?;
        //             let s1 = self.xor(
        //                 &s1,
        //                 &self.shift_right(
        //                     &message_schedule[i - 2],
        //                     &mut region,
        //                     &self.config,
        //                     10,
        //                     i % 4,
        //                 )?,
        //                 &mut region,
        //                 &self.config,
        //                 i % 4,
        //             )?;

        //             let sum = self.add(
        //                 &message_schedule[i - 16],
        //                 &s0,
        //                 &mut region,
        //                 &self.config,
        //                 i % 4,
        //             )?;
        //             let new_word = self.add(
        //                 &sum,
        //                 &message_schedule[i - 7],
        //                 &mut region,
        //                 &self.config,
        //                 i % 4,
        //             )?;
        //             let new_word = self.add(&new_word, &s1, &mut region, &self.config, i % 4)?;

        //             message_schedule.push(new_word);
        //         }

        //         Ok(())
        //     },
        // )?;

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

    // Compression function F takes as an argument the state vector "h",
    // message block vector "m" (last block is padded with zeros to full
    // block size, if required), 2w-bit offset counter "t", and final block
    // indicator flag "f".  Local vector v[0..15] is used in processing.  F
    // returns a new state vector.  The number of rounds, "r", is 12 for
    // BLAKE2b and 10 for BLAKE2s.  Rounds are numbered from 0 to r - 1.
 
    //     FUNCTION F( h[0..7], m[0..15], t, f )
    //     |
    //     |      // Initialize local work vector v[0..15]
    //     |      v[0..7] := h[0..7]              // First half from state.
    //     |      v[8..15] := IV[0..7]            // Second half from IV.
    //     |
    //     |      v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
    //     |      v[13] := v[13] ^ (t >> w)       // High word.
    //     |
    //     |      IF f = TRUE THEN                // last block flag?
    //     |      |   v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
    //     |      END IF.
    //     |
    //     |      // Cryptographic mixing
    //     |      FOR i = 0 TO r - 1 DO           // Ten or twelve rounds.
    //     |      |
    //     |      |   // Message word selection permutation for this round.
    //     |      |   s[0..15] := SIGMA[i mod 10][0..15]
    //     |      |
    //     |      |   v := G( v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]] )
    //     |      |   v := G( v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]] )
    //     |      |   v := G( v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]] )
    //     |      |   v := G( v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]] )
    //     |      |
    //     |      |   v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
    //     |      |   v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
    //     |      |   v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
    //     |      |   v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )
    //     |      |
    //     |      END FOR
    //     |
    //     |      FOR i = 0 TO 7 DO               // XOR the two halves.
    //     |      |   h[i] := h[i] ^ v[i] ^ v[i + 8]
    //     |      END FOR.
    //     |
    //     |      RETURN h[0..7]                  // New state.
    //     |
    //     END FUNCTION.
    fn compression_function(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 8],
        message_block: [AssignedCell<pallas::Base, pallas::Base>; 16],
        counter: u64,
        flag: bool
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 8], Error> {
        let mut v = [pallas::Base::zero(); 16]; 

        v[0..8].copy_from_slice(&state[0..8]);    // Copy first half from state h
        v[8..16].copy_from_slice(&IV[0..8]);  // Copy second half from IV

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
    pub state: [pallas::Base; 16],
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

        let state: [AssignedCell<pallas::Base, pallas::Base>; 16] = state.try_into().unwrap();
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
        let state: [pallas::Base; 16] = (0..16).map(pallas::Base::from).collect().try_into().unwrap();

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
