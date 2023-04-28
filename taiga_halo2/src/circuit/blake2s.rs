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
const SIGMA: [[usize; 16]; 10] = [
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

const ROUNDS: usize = 10;

// ---------------

#[derive(Clone, Debug)]
pub struct Blake2sChip<F: Field> {
    config: Blake2sConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sConfig {
    pub v: [Column<Advice>; 4],
    pub u: Column<Fixed>,
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

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let u = meta.fixed_column();
        meta.enable_constant(u);
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

    // TODO: Use lookups - see sha256 implementation as reference
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
            region.assign_advice(|| "xor", config.v[offset], offset, || result_val)?;

        Ok(result_cell)
    }

    fn add_mod_u32(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        y: &AssignedCell<pallas::Base, pallas::Base>,
        region: &mut Region<'_, pallas::Base>,
        config: &Blake2sConfig,
        offset: usize,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        let result_val = x.value().zip(y.value()).map(|(x_val, y_val)| {
            // Convert the Pallas base field element into bytes
            let x_bytes = x_val.to_repr();
            let x_u32 = u32::from_le_bytes([x_bytes[0], x_bytes[1], x_bytes[2], x_bytes[3]]);
            let y_bytes = y_val.to_repr();
            let y_u32 = u32::from_le_bytes([y_bytes[0], y_bytes[1], y_bytes[2], y_bytes[3]]);
            pallas::Base::from((x_u32 + y_u32) as u64)
        });

        // Take the first 4 bytes to create a u32 integer (considering endianness)

        let result_cell =
            region.assign_advice(|| "add", config.v[offset], offset, || result_val)?;

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
            let rotation_factor =
                pallas::Base::from(2).pow_vartime(&[(num_bits - k_mod_num_bits) as u64]);

            v * rotation_factor
        });
        let rotated_cell = region.assign_advice(
            || format!("rotate {}", rotation),
            config.v[offset],
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
            config.v[offset],
            offset,
            || shifted_value,
        )?;

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
        a: usize,
        b: usize,
        c: usize,
        d: usize,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 16], Error> {
        layouter.assign_region(
            || "G function",
            |mut region| {
                let x = &message[0];
                let y = &message[1];
                let va = &state[a];
                let vb = &state[b];
                let vc = &state[c];
                let vd = &state[d];

                // First mixing stage
                let va = self.add_mod_u32(va, vb, &mut region, &self.config, round % 4)?;
                let va = self.add_mod_u32(&va, &x, &mut region, &self.config, round % 4)?;

                let vd = self.xor(vd, &va, &mut region, &self.config, round % 4)?;
                let vd = self.rotate_right(&vd, &mut region, &self.config, R1, round % 4)?;

                let vc = self.add_mod_u32(vc, &vd, &mut region, &self.config, round % 4)?;

                let vb = self.xor(&vb, &vc, &mut region, &self.config, round % 4)?;
                let vb = self.rotate_right(&vb, &mut region, &self.config, R2, round % 4)?;

                // Second mixing stage
                let va = self.add_mod_u32(&va, &vb, &mut region, &self.config, round % 4)?;
                let va = self.add_mod_u32(&va, &y, &mut region, &self.config, round % 4)?;

                let vd = self.xor(&vd, &va, &mut region, &self.config, round % 4)?;
                let vd = self.rotate_right(&vd, &mut region, &self.config, R3, round % 4)?;

                let vc = self.add_mod_u32(&vc, &vd, &mut region, &self.config, round % 4)?;

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
    fn f(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        state: [AssignedCell<pallas::Base, pallas::Base>; 8],
        message_block: [AssignedCell<pallas::Base, pallas::Base>; 16],
        // counter: u64,
        // flag: bool,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 8], Error> {
        let mut v_vec: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::with_capacity(16);

        for i in 0..8 {
            v_vec.push(state[i].clone()); // Copy first half from state h
        }
        let mut iv_cells: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::with_capacity(8);

        layouter.assign_region(
            || "IV Cells",
            |mut region| {
                for i in 0..8 {
                    let c = region.assign_advice_from_constant(
                        || "iv",
                        self.config.v[i % 4],
                        0,
                        pallas::Base::from(IV[i] as u64),
                    )?;
                    iv_cells.push(c);
                }
                Ok(())
            },
        )?;

        for i in 0..8 {
            v_vec.push(iv_cells[i].clone()); // Copy second half from IV
        }

        // Convert the Vec to a fixed-size array
        let mut v: [AssignedCell<pallas::Base, pallas::Base>; 16] =
            v_vec.try_into().expect("Vec length mismatch");

        // TODO
        //     |      v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
        //     |      v[13] := v[13] ^ (t >> w)       // High word.
        //     |
        //     |      IF f = TRUE THEN                // last block flag?
        //     |      |   v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
        //     |      END IF.

        // 2. Perform the 10 rounds of the Blake2s compression function
        for round in 0..ROUNDS {
            let s = SIGMA[round];
            for i in 0..4 {
                v = self.g(
                    layouter,
                    v,
                    [
                        message_block[s[2 * i]].clone(),
                        message_block[s[2 * i + 1]].clone(),
                    ],
                    round,
                    i,
                    i + 4,
                    i + 8,
                    i + 12,
                )?;
            }
            //  v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
            v = self.g(
                layouter,
                v,
                [message_block[s[8]].clone(), message_block[s[9]].clone()],
                round,
                0,
                5,
                10,
                15,
            )?;
            // v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
            v = self.g(
                layouter,
                v,
                [message_block[s[10]].clone(), message_block[s[11]].clone()],
                round,
                1,
                6,
                11,
                12,
            )?;
            // v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
            v = self.g(
                layouter,
                v,
                [message_block[s[12]].clone(), message_block[s[13]].clone()],
                round,
                2,
                7,
                8,
                13,
            )?;
            // v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )
            v = self.g(
                layouter,
                v,
                [message_block[s[10]].clone(), message_block[s[9]].clone()],
                round,
                3,
                4,
                9,
                14,
            )?;
        }

        // 3. Finalize the state
        let final_state = layouter.assign_region(
            || "Finalize state",
            |mut region| {
                let mut final_state = Vec::with_capacity(8);
                for i in 0..8 {
                    let a = self.xor(&state[i], &v[i], &mut region, self.config(), i % 4)?;
                    let b = self.xor(&a, &v[i + 8], &mut region, self.config(), i % 4)?;

                    final_state.push(b);
                }
                Ok(final_state.try_into().unwrap())
            },
        )?;

        Ok(final_state)
    }

    // Key and data input are split and padded into "dd" message blocks
    // d[0..dd-1], each consisting of 16 words (or "bb" bytes).

    // If a secret key is used (kk > 0), it is padded with zero bytes and
    // set as d[0].  Otherwise, d[0] is the first data block.  The final
    // data block d[dd-1] is also padded with zero to "bb" bytes (16 words).

    // The number of blocks is therefore dd = ceil(kk / bb) + ceil(ll / bb).
    // However, in the special case of an unkeyed empty message (kk = 0 and
    // ll = 0), we still set dd = 1 and d[0] consists of all zeros.

    // The following procedure processes the padded data blocks into an
    // "nn"-byte final hash value.
    // FUNCTION BLAKE2( d[0..dd-1], ll, kk, nn )
    //     |
    //     |     h[0..7] := IV[0..7]          // Initialization Vector.
    //     |
    //     |     // Parameter block p[0]
    //     |     h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn
    //     |
    //     |     // Process padded key and data blocks
    //     |     IF dd > 1 THEN
    //     |     |       FOR i = 0 TO dd - 2 DO
    //     |     |       |       h := F( h, d[i], (i + 1) * bb, FALSE )
    //     |     |       END FOR.
    //     |     END IF.
    //     |
    //     |     // Final block.
    //     |     IF kk = 0 THEN
    //     |     |       h := F( h, d[dd - 1], ll, TRUE )
    //     |     ELSE
    //     |     |       h := F( h, d[dd - 1], ll + bb, TRUE )
    //     |     END IF.
    //     |
    //     |     RETURN first "nn" bytes from little-endian word array h[].
    //     |
    //     END FUNCTION.
    fn blake2s(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        message: [pallas::Base; 16], // TODO: Message blocks
                                     // input_bytes: u64, // 0 <= ll < 2**64
                                     // key_bytes: u32, // 1 <= kk <= 32
                                     // hash_bytes: u32, // 1 <= nn <= 32
                                     // dd: u32 // dd = ceil(kk / bb) + ceil(ll / bb)
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 8], Error> {
        // Initialization Vector.
        let mut state: [AssignedCell<pallas::Base, pallas::Base>; 8] = layouter
            .assign_region(
                || "assign state",
                |mut region| {
                    let mut state_cells = Vec::new();
                    for (idx, value) in IV.iter().enumerate() {
                        let cell = region.assign_advice_from_constant(
                            || "state",
                            self.config.v[idx % 4],
                            0,
                            pallas::Base::from(*value as u64),
                        )?;
                        state_cells.push(cell);
                    }
                    Ok(state_cells)
                },
            )?
            .try_into()
            .unwrap();

        let message_block: [AssignedCell<pallas::Base, pallas::Base>; 16] = layouter
            .assign_region(
                || "assign message block",
                |mut region| {
                    let mut message_cells = Vec::new();
                    for (idx, value) in message.iter().enumerate() {
                        let cell = region.assign_advice_from_constant(
                            || "message",
                            self.config.v[idx % 4],
                            0,
                            *value,
                        )?;
                        message_cells.push(cell);
                    }
                    Ok(message_cells)
                },
            )?
            .try_into()
            .unwrap();

        // Parameter block p[0]
        // TODO     h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn

        // TODO: Process padded key and data blocks
        // |     IF dd > 1 THEN
        // |     |       FOR i = 0 TO dd - 2 DO
        // |     |       |       h := F( h, d[i], (i + 1) * bb, FALSE )
        // |     |       END FOR.
        // |     END IF.
        // |

        state = self.f(layouter, state, message_block)?;
        Ok(state)
    }
}

#[derive(Clone, Debug, Default)]
pub struct TestCircuit {
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

        let output_state = blake2s_chip.blake2s(&mut layouter, self.message_block)?;

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
            message_block,
            expected_output,
        };

        // Set the number of rows for the circuit.
        let n = 12;

        // Create a mock prover for the circuit.
        let mut prover = MockProver::<pallas::Base>::run(n, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
