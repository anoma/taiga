use super::gadgets::assign_free_advice;
use crate::circuit::gadgets::assign_free_constant;
use crate::constant::{
    VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_1, VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_2,
    VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_1, VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_2,
    VP_COMMITMENT_PERSONALIZATION,
};
use crate::vp_commitment::ValidityPredicateCommitment;
use byteorder::{ByteOrder, LittleEndian};
use group::ff::PrimeField;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Error, Instance, Selector, VirtualCells,
    },
    poly::Rotation,
};
use std::{convert::TryInto, marker::PhantomData};

pub fn vp_commitment_gadget<F: PrimeField>(
    layouter: &mut impl Layouter<F>,
    blake2s_chip: &Blake2sChip<F>,
    vp: AssignedCell<F, F>,
    rcm: AssignedCell<F, F>,
) -> Result<[AssignedCell<F, F>; 2], Error> {
    let hash = blake2s_chip.process(layouter, &[vp, rcm], VP_COMMITMENT_PERSONALIZATION)?;
    blake2s_chip.encode_result(layouter, &hash)
}

pub fn publicize_default_dynamic_vp_commitments<F: PrimeField>(
    layouter: &mut impl Layouter<F>,
    advice: Column<Advice>,
    instances: Column<Instance>,
) -> Result<(), Error> {
    let vp_cm_fields: [F; 2] = ValidityPredicateCommitment::default().to_public_inputs();
    let vp_cm_1 = assign_free_advice(
        layouter.namespace(|| "vp_cm 1"),
        advice,
        Value::known(vp_cm_fields[0]),
    )?;
    let vp_cm_2 = assign_free_advice(
        layouter.namespace(|| "vp_cm 2"),
        advice,
        Value::known(vp_cm_fields[1]),
    )?;

    layouter.constrain_instance(vp_cm_1.cell(), instances, VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_1)?;
    layouter.constrain_instance(vp_cm_2.cell(), instances, VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_2)?;
    layouter.constrain_instance(vp_cm_1.cell(), instances, VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_1)?;
    layouter.constrain_instance(vp_cm_2.cell(), instances, VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_2)?;

    Ok(())
}

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
const R1: usize = 16;
const R2: usize = 12;
const R3: usize = 8;
const R4: usize = 7;

const ROUNDS: usize = 10;

// ---------------

#[derive(Clone, Debug)]
pub struct Blake2sChip<F: PrimeField> {
    config: Blake2sConfig<F>,
    _marker: PhantomData<F>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sConfig<F: PrimeField> {
    pub advices: [Column<Advice>; 10],
    pub s_field_decompose: Selector,
    pub s_word_decompose: Selector,
    pub s_byte_decompose: Selector,
    pub s_byte_xor: Selector,
    pub s_word_add: Selector,
    pub s_result_encode: Selector,
    _marker: PhantomData<F>,
}

// One blockword has 4 bytes(32bits).
#[derive(Clone, Debug)]
pub struct Blake2sWord<F: PrimeField> {
    word: AssignedCell<F, F>,
    bits: [AssignedCell<F, F>; 32],
}

// One byte has 8 bits.
#[derive(Clone, Debug)]
struct Blake2sByte<F: PrimeField> {
    byte: AssignedCell<F, F>,
    bits: [AssignedCell<F, F>; 8],
}

impl<F: PrimeField> Blake2sByte<F> {
    pub fn get_byte(&self) -> AssignedCell<F, F> {
        self.byte.clone()
    }

    pub fn get_bits(&self) -> &[AssignedCell<F, F>; 8] {
        &self.bits
    }

    pub fn from_u8(
        value: Value<u8>,
        mut layouter: impl Layouter<F>,
        config: &Blake2sConfig<F>,
    ) -> Result<Self, Error> {
        layouter.assign_region(
            || "decompose bytes to bits",
            |mut region| {
                config.s_byte_decompose.enable(&mut region, 0)?;
                let mut byte = value;
                let mut bits = Vec::with_capacity(8);
                for i in 0..8 {
                    let bit = byte.map(|b| F::from((b & 1) as u64));
                    let bit_var = region.assign_advice(|| "bit", config.advices[i], 0, || bit)?;
                    bits.push(bit_var);
                    byte = byte.map(|b| b >> 1);
                }
                let byte = region.assign_advice(
                    || "byte",
                    config.advices[0],
                    1,
                    || value.map(|v| F::from(v as u64)),
                )?;
                Ok(Self {
                    byte,
                    bits: bits.try_into().unwrap(),
                })
            },
        )
    }

    pub fn from_constant_u8(
        value: u8,
        layouter: &mut impl Layouter<F>,
        config: &Blake2sConfig<F>,
    ) -> Result<Self, Error> {
        layouter.assign_region(
            || "decompose bytes to bits",
            |mut region| {
                config.s_byte_decompose.enable(&mut region, 0)?;
                let mut byte = value;
                let mut bits = Vec::with_capacity(8);
                for i in 0..8 {
                    let bit = byte & 1;
                    let bit_var = region.assign_advice_from_constant(
                        || "bit",
                        config.advices[i],
                        0,
                        F::from(bit as u64),
                    )?;
                    bits.push(bit_var);
                    byte >>= 1;
                }
                let byte = region.assign_advice_from_constant(
                    || "byte",
                    config.advices[0],
                    1,
                    F::from(value as u64),
                )?;
                Ok(Self {
                    byte,
                    bits: bits.try_into().unwrap(),
                })
            },
        )
    }
}

impl<F: PrimeField> Blake2sConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; 10],
    ) -> Blake2sConfig<F> {
        let s_field_decompose = meta.selector();
        let s_word_decompose = meta.selector();
        let s_byte_decompose = meta.selector();
        let s_byte_xor = meta.selector();
        let s_word_add = meta.selector();
        let s_result_encode = meta.selector();

        meta.create_gate("decompose field to words", |meta| {
            let field_element = meta.query_advice(advices[0], Rotation::next());
            let word_1 = meta.query_advice(advices[0], Rotation::cur());
            let word_2 = meta.query_advice(advices[1], Rotation::cur());
            let word_3 = meta.query_advice(advices[2], Rotation::cur());
            let word_4 = meta.query_advice(advices[3], Rotation::cur());
            let word_5 = meta.query_advice(advices[4], Rotation::cur());
            let word_6 = meta.query_advice(advices[5], Rotation::cur());
            let word_7 = meta.query_advice(advices[6], Rotation::cur());
            let word_8 = meta.query_advice(advices[7], Rotation::cur());
            let s_field_decompose = meta.query_selector(s_field_decompose);

            vec![
                s_field_decompose
                    * (word_1
                        + word_2 * F::from(1 << 32)
                        + word_3 * F::from_u128(1 << 64)
                        + word_4 * F::from_u128(1 << 96)
                        + word_5 * F::from_u128(1 << 64).square()
                        + word_6 * F::from_u128(1 << 80).square()
                        + word_7 * F::from_u128(1 << 96).square()
                        + word_8 * F::from_u128(1 << 112).square()
                        - field_element),
            ]
        });

        meta.create_gate("decompose word to bytes", |meta| {
            let word = meta.query_advice(advices[0], Rotation::next());
            let byte_1 = meta.query_advice(advices[0], Rotation::cur());
            let byte_2 = meta.query_advice(advices[1], Rotation::cur());
            let byte_3 = meta.query_advice(advices[2], Rotation::cur());
            let byte_4 = meta.query_advice(advices[3], Rotation::cur());
            let s_word_decompose = meta.query_selector(s_word_decompose);

            vec![
                s_word_decompose
                    * (byte_1
                        + byte_2 * F::from(1 << 8)
                        + byte_3 * F::from(1 << 16)
                        + byte_4 * F::from(1 << 24)
                        - word),
            ]
        });

        meta.create_gate("decompose byte to bits", |meta| {
            let byte = meta.query_advice(advices[0], Rotation::next());
            let bit_1 = meta.query_advice(advices[0], Rotation::cur());
            let bit_2 = meta.query_advice(advices[1], Rotation::cur());
            let bit_3 = meta.query_advice(advices[2], Rotation::cur());
            let bit_4 = meta.query_advice(advices[3], Rotation::cur());
            let bit_5 = meta.query_advice(advices[4], Rotation::cur());
            let bit_6 = meta.query_advice(advices[5], Rotation::cur());
            let bit_7 = meta.query_advice(advices[6], Rotation::cur());
            let bit_8 = meta.query_advice(advices[7], Rotation::cur());
            let s_byte_decompose = meta.query_selector(s_byte_decompose);

            vec![
                s_byte_decompose
                    * (bit_1
                        + bit_2 * F::from(1 << 1)
                        + bit_3 * F::from(1 << 2)
                        + bit_4 * F::from(1 << 3)
                        + bit_5 * F::from(1 << 4)
                        + bit_6 * F::from(1 << 5)
                        + bit_7 * F::from(1 << 6)
                        + bit_8 * F::from(1 << 7)
                        - byte),
            ]
        });

        meta.create_gate("byte xor", |meta| {
            let s_byte_xor = meta.query_selector(s_byte_xor);
            let bit_xor = |idx: usize, meta: &mut VirtualCells<F>| {
                let lhs_bit = meta.query_advice(advices[idx], Rotation::prev());
                let rhs_bit = meta.query_advice(advices[idx], Rotation::cur());
                let out_bit = meta.query_advice(advices[idx], Rotation::next());
                lhs_bit.clone() + rhs_bit.clone() - lhs_bit * rhs_bit * F::from(2) - out_bit
            };

            Constraints::with_selector(
                s_byte_xor,
                std::iter::empty()
                    .chain((0..8).map(|idx| bit_xor(idx, meta)))
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("word add", |meta| {
            let s_word_add = meta.query_selector(s_word_add);
            let lhs = meta.query_advice(advices[0], Rotation::cur());
            let rhs = meta.query_advice(advices[1], Rotation::cur());
            let out = meta.query_advice(advices[0], Rotation::next());
            let carry = meta.query_advice(advices[1], Rotation::next());
            let equal = lhs + rhs - carry.clone() * F::from(1 << 32) - out;

            Constraints::with_selector(
                s_word_add,
                [
                    ("carry bool check", bool_check(carry)),
                    ("equal check", equal),
                ],
            )
        });

        meta.create_gate("encode four words to one field", |meta| {
            let field_element = meta.query_advice(advices[0], Rotation::next());
            let word_1 = meta.query_advice(advices[0], Rotation::cur());
            let word_2 = meta.query_advice(advices[1], Rotation::cur());
            let word_3 = meta.query_advice(advices[2], Rotation::cur());
            let word_4 = meta.query_advice(advices[3], Rotation::cur());
            let s_result_encode = meta.query_selector(s_result_encode);

            vec![
                s_result_encode
                    * (word_1
                        + word_2 * F::from(1 << 32)
                        + word_3 * F::from_u128(1 << 64)
                        + word_4 * F::from_u128(1 << 96)
                        - field_element),
            ]
        });

        Blake2sConfig {
            advices,
            s_field_decompose,
            s_word_decompose,
            s_byte_decompose,
            s_byte_xor,
            s_word_add,
            s_result_encode,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> Blake2sChip<F> {
    pub fn construct(config: Blake2sConfig<F>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn process(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: &[AssignedCell<F, F>],
        personalization: &[u8],
    ) -> Result<Vec<Blake2sWord<F>>, Error> {
        assert_eq!(personalization.len(), 8);
        assert!(inputs.len() % 2 == 0);

        // Init
        let mut h = vec![
            Blake2sWord::from_constant_u32(IV[0] ^ 0x01010000 ^ 32, layouter, self)?,
            Blake2sWord::from_constant_u32(IV[1], layouter, self)?,
            Blake2sWord::from_constant_u32(IV[2], layouter, self)?,
            Blake2sWord::from_constant_u32(IV[3], layouter, self)?,
            Blake2sWord::from_constant_u32(IV[4], layouter, self)?,
            Blake2sWord::from_constant_u32(IV[5], layouter, self)?,
            Blake2sWord::from_constant_u32(
                IV[6] ^ LittleEndian::read_u32(&personalization[0..4]),
                layouter,
                self,
            )?,
            Blake2sWord::from_constant_u32(
                IV[7] ^ LittleEndian::read_u32(&personalization[4..8]),
                layouter,
                self,
            )?,
        ];

        // Handle message: convert field message to blocks.
        let mut blocks = vec![];
        for block in inputs.chunks(2) {
            let mut cur_block = Vec::with_capacity(16);
            for field in block.iter() {
                let mut words = self.field_decompose(layouter, field)?;
                cur_block.append(&mut words);
            }
            blocks.push(cur_block);
        }

        if blocks.is_empty() {
            let zero_padding_block = (0..16)
                .map(|_| Blake2sWord::from_constant_u32(0, layouter, self).unwrap())
                .collect();
            blocks.push(zero_padding_block);
        }

        let block_len = blocks.len();

        for (i, block) in blocks[0..(block_len - 1)].iter().enumerate() {
            self.compress(layouter, &mut h, block, (i as u64 + 1) * 64, false)?;
        }

        // Compress(Final block)
        self.compress(
            layouter,
            &mut h,
            &blocks[block_len - 1],
            (block_len as u64) * 64,
            true,
        )?;

        Ok(h)
    }

    // Encode the eight words to two field elements
    pub fn encode_result(
        &self,
        layouter: &mut impl Layouter<F>,
        ret: &Vec<Blake2sWord<F>>,
    ) -> Result<[AssignedCell<F, F>; 2], Error> {
        let mut fields = vec![];
        assert_eq!(ret.len(), 8);
        for words in ret.chunks(4) {
            let field = layouter.assign_region(
                || "encode four words to one field",
                |mut region| {
                    self.config.s_result_encode.enable(&mut region, 0)?;
                    for (i, word) in words.iter().enumerate() {
                        word.get_word().copy_advice(
                            || "word",
                            &mut region,
                            self.config.advices[i],
                            0,
                        )?;
                    }
                    let word_values: Value<Vec<_>> =
                        words.iter().map(|word| word.get_word().value()).collect();
                    let field_value = word_values.map(|words| {
                        words
                            .into_iter()
                            .rev()
                            .fold(F::ZERO, |acc, byte| acc * F::from(1 << 32) + byte)
                    });
                    region.assign_advice(
                        || "result field",
                        self.config.advices[0],
                        1,
                        || field_value,
                    )
                },
            )?;
            fields.push(field);
        }
        assert_eq!(fields.len(), 2);
        Ok(fields.try_into().unwrap())
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
    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        h: &mut [Blake2sWord<F>], // current state
        m: &[Blake2sWord<F>],     // current block
        t: u64,                   // offset counter
        f: bool,                  // final flag
    ) -> Result<(), Error> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(h);
        for iv in IV[0..4].iter() {
            let word = Blake2sWord::from_constant_u32(*iv, layouter, self)?;
            v.push(word);
        }
        // v[12] := v[12] ^ (t mod 2**w)
        let v_12 = Blake2sWord::from_constant_u32(IV[4] ^ (t as u32), layouter, self)?;
        v.push(v_12);

        // v[13] := v[13] ^ (t >> w)
        let v_13 = Blake2sWord::from_constant_u32(IV[5] ^ ((t >> 32) as u32), layouter, self)?;
        v.push(v_13);

        // IF f = TRUE THEN                // last block flag?
        // |   v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
        // END IF.
        let v_14 = if f {
            Blake2sWord::from_constant_u32(IV[6] ^ u32::max_value(), layouter, self)?
        } else {
            Blake2sWord::from_constant_u32(IV[6], layouter, self)?
        };
        v.push(v_14);

        // v_15
        let v_15 = Blake2sWord::from_constant_u32(IV[7], layouter, self)?;
        v.push(v_15);
        assert_eq!(v.len(), 16);

        for i in 0..ROUNDS {
            let s = SIGMA[i % ROUNDS];
            self.g(
                layouter.namespace(|| "mixing 1"),
                &mut v,
                (0, 4, 8, 12),
                &m[s[0]],
                &m[s[1]],
            )?;
            self.g(
                layouter.namespace(|| "mixing 2"),
                &mut v,
                (1, 5, 9, 13),
                &m[s[2]],
                &m[s[3]],
            )?;
            self.g(
                layouter.namespace(|| "mixing 3"),
                &mut v,
                (2, 6, 10, 14),
                &m[s[4]],
                &m[s[5]],
            )?;
            self.g(
                layouter.namespace(|| "mixing 4"),
                &mut v,
                (3, 7, 11, 15),
                &m[s[6]],
                &m[s[7]],
            )?;

            self.g(
                layouter.namespace(|| "mixing 5"),
                &mut v,
                (0, 5, 10, 15),
                &m[s[8]],
                &m[s[9]],
            )?;
            self.g(
                layouter.namespace(|| "mixing 6"),
                &mut v,
                (1, 6, 11, 12),
                &m[s[10]],
                &m[s[11]],
            )?;
            self.g(
                layouter.namespace(|| "mixing 7"),
                &mut v,
                (2, 7, 8, 13),
                &m[s[12]],
                &m[s[13]],
            )?;
            self.g(
                layouter.namespace(|| "mixing 8"),
                &mut v,
                (3, 4, 9, 14),
                &m[s[14]],
                &m[s[15]],
            )?;
        }

        // Finalize the state
        for i in 0..8 {
            let h_i_bits = self.word_xor(
                layouter.namespace(|| "final first xor"),
                h[i].get_bits(),
                v[i].get_bits(),
            )?;
            let h_i_bits = self.word_xor(
                layouter.namespace(|| "final second xor"),
                &h_i_bits,
                v[i + 8].get_bits(),
            )?;
            h[i] = Blake2sWord::from_bits(
                self,
                layouter.namespace(|| "construct word from bits"),
                h_i_bits,
            )?;
        }

        Ok(())
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
        mut layouter: impl Layouter<F>,
        v: &mut [Blake2sWord<F>],
        (a, b, c, d): (usize, usize, usize, usize),
        x: &Blake2sWord<F>,
        y: &Blake2sWord<F>,
    ) -> Result<(), Error> {
        // v[a] := (v[a] + v[b] + x) mod 2**w
        v[a] = {
            let sum_a_b = self.add_mod_u32(
                layouter.namespace(|| "add_mod_u32"),
                v[a].get_word(),
                v[b].get_word(),
            )?;
            let sum_a_b_x =
                self.add_mod_u32(layouter.namespace(|| "add_mod_u32"), &sum_a_b, x.get_word())?;
            Blake2sWord::from_word(self, layouter.namespace(|| "from word"), sum_a_b_x)?
        };

        // v[d] := (v[d] ^ v[a]) >>> R1
        v[d] = {
            let d_xor_a = self.word_xor(
                layouter.namespace(|| "xor"),
                v[d].get_bits(),
                v[a].get_bits(),
            )?;
            let bits = Blake2sWord::word_rotate(&d_xor_a, R1);
            Blake2sWord::from_bits(self, layouter.namespace(|| "from bits"), bits)?
        };

        // v[c] := (v[c] + v[d])     mod 2**w
        v[c] = {
            let sum = self.add_mod_u32(
                layouter.namespace(|| "add_mod_u32"),
                v[c].get_word(),
                v[d].get_word(),
            )?;
            Blake2sWord::from_word(self, layouter.namespace(|| "from word"), sum)?
        };

        // v[b] := (v[b] ^ v[c]) >>> R2
        v[b] = {
            let b_xor_c = self.word_xor(
                layouter.namespace(|| "xor"),
                v[b].get_bits(),
                v[c].get_bits(),
            )?;
            let bits = Blake2sWord::word_rotate(&b_xor_c, R2);
            Blake2sWord::from_bits(self, layouter.namespace(|| "from bits"), bits)?
        };

        // v[a] := (v[a] + v[b] + y) mod 2**w
        v[a] = {
            let sum_a_b = self.add_mod_u32(
                layouter.namespace(|| "add_mod_u32"),
                v[a].get_word(),
                v[b].get_word(),
            )?;
            let sum_a_b_y =
                self.add_mod_u32(layouter.namespace(|| "add_mod_u32"), &sum_a_b, y.get_word())?;
            Blake2sWord::from_word(self, layouter.namespace(|| "from word"), sum_a_b_y)?
        };

        // v[d] := (v[d] ^ v[a]) >>> R3
        v[d] = {
            let d_xor_a = self.word_xor(
                layouter.namespace(|| "xor"),
                v[d].get_bits(),
                v[a].get_bits(),
            )?;
            let bits = Blake2sWord::word_rotate(&d_xor_a, R3);
            Blake2sWord::from_bits(self, layouter.namespace(|| "from bits"), bits)?
        };

        // v[c] := (v[c] + v[d])     mod 2**w
        v[c] = {
            let sum = self.add_mod_u32(
                layouter.namespace(|| "add_mod_u32"),
                v[c].get_word(),
                v[d].get_word(),
            )?;
            Blake2sWord::from_word(self, layouter.namespace(|| "from word"), sum)?
        };

        // v[b] := (v[b] ^ v[c]) >>> R4
        v[b] = {
            let b_xor_c = self.word_xor(
                layouter.namespace(|| "xor"),
                v[b].get_bits(),
                v[c].get_bits(),
            )?;
            let bits = Blake2sWord::word_rotate(&b_xor_c, R4);
            Blake2sWord::from_bits(self, layouter.namespace(|| "from bits"), bits)?
        };

        Ok(())
    }

    // Decompose a field to words
    fn field_decompose(
        &self,
        layouter: &mut impl Layouter<F>,
        field: &AssignedCell<F, F>,
    ) -> Result<Vec<Blake2sWord<F>>, Error> {
        // the decomposition from bytes to bits
        let mut bits = vec![];
        let mut bytes = vec![];
        for i in 0..32 {
            let byte_value = field.value().map(|f| f.to_repr().as_ref()[i]);
            let byte =
                Blake2sByte::from_u8(byte_value, layouter.namespace(|| "from_u8"), &self.config)?;
            bits.append(&mut byte.get_bits().to_vec());
            bytes.push(byte.get_byte());
        }

        // Check the decomposition from words to bytes
        let mut words = vec![];
        for bytes in bytes.chunks(4) {
            let word = {
                let byte_values: Value<Vec<_>> = bytes.iter().map(|byte| byte.value()).collect();
                let word_value = byte_values.map(|bytes| {
                    bytes
                        .into_iter()
                        .rev()
                        .fold(F::ZERO, |acc, byte| acc * F::from(1 << 8) + byte)
                });
                assign_free_advice(
                    layouter.namespace(|| "assign word"),
                    self.config.advices[8],
                    word_value,
                )?
            };
            self.word_decompose(layouter.namespace(|| "word decompose"), bytes, &word)?;
            words.push(word);
        }

        // check the decomposition from field to words
        layouter.assign_region(
            || "decompose field to words",
            |mut region| {
                self.config.s_field_decompose.enable(&mut region, 0)?;
                for (i, word) in words.iter().enumerate() {
                    word.copy_advice(|| "word", &mut region, self.config.advices[i], 0)?;
                }
                field.copy_advice(|| "field", &mut region, self.config.advices[0], 1)?;
                Ok(())
            },
        )?;

        let res = bits
            .chunks(32)
            .zip(words)
            .map(|(bits, word)| Blake2sWord {
                word,
                bits: bits.to_vec().try_into().unwrap(),
            })
            .collect::<Vec<_>>();

        Ok(res)
    }

    // decompose a word to four bytes
    fn word_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        bytes: &[AssignedCell<F, F>],
        word: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        assert_eq!(bytes.len(), 4);
        layouter.assign_region(
            || "decompose word to bytes",
            |mut region| {
                self.config.s_word_decompose.enable(&mut region, 0)?;
                for (i, byte) in bytes.iter().enumerate() {
                    byte.copy_advice(|| "byte", &mut region, self.config.advices[i], 0)?;
                }
                word.copy_advice(|| "word", &mut region, self.config.advices[0], 1)?;
                Ok(())
            },
        )
    }

    // decompose from a byte to eight bits
    fn byte_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        bits: &[AssignedCell<F, F>],
        byte: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        assert_eq!(bits.len(), 8);
        layouter.assign_region(
            || "decompose byte to bits",
            |mut region| {
                self.config.s_byte_decompose.enable(&mut region, 0)?;
                for (i, bit) in bits.iter().enumerate() {
                    bit.copy_advice(|| "bit", &mut region, self.config.advices[i], 0)?;
                }
                byte.copy_advice(|| "byte", &mut region, self.config.advices[0], 1)?;
                Ok(())
            },
        )
    }

    fn byte_xor(
        &self,
        mut layouter: impl Layouter<F>,
        x: &[AssignedCell<F, F>],
        y: &[AssignedCell<F, F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(x.len(), 8);
        assert_eq!(y.len(), 8);
        layouter.assign_region(
            || "byte xor",
            |mut region| {
                self.config.s_byte_xor.enable(&mut region, 1)?;
                let xor = |x: &F, y: &F| -> F {
                    F::from(((x.is_odd()) ^ (y.is_odd())).unwrap_u8() as u64)
                };
                let mut byte_ret = Vec::with_capacity(8);
                for i in 0..8 {
                    x[i].copy_advice(|| "xor bit x", &mut region, self.config.advices[i], 0)?;
                    y[i].copy_advice(|| "xor bit y", &mut region, self.config.advices[i], 1)?;
                    let result_bits = x[i]
                        .value()
                        .zip(y[i].value())
                        .map(|(x_bit, y_bit)| xor(x_bit, y_bit));
                    let ret = region.assign_advice(
                        || "xor bit result",
                        self.config.advices[i],
                        2,
                        || result_bits,
                    )?;
                    byte_ret.push(ret);
                }

                Ok(byte_ret)
            },
        )
    }

    fn word_xor(
        &self,
        mut layouter: impl Layouter<F>,
        x: &[AssignedCell<F, F>],
        y: &[AssignedCell<F, F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        let mut bits = Vec::with_capacity(32);
        for (x_byte, y_byte) in x.chunks(8).zip(y.chunks(8)) {
            let mut ret = self.byte_xor(layouter.namespace(|| "byte xor"), x_byte, y_byte)?;
            bits.append(&mut ret);
        }

        Ok(bits)
    }

    fn add_mod_u32(
        &self,
        mut layouter: impl Layouter<F>,
        // x and y must be a word variable
        x: &AssignedCell<F, F>,
        y: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "decompose bytes to bits",
            |mut region| {
                self.config.s_word_add.enable(&mut region, 0)?;
                x.copy_advice(|| "word_add x", &mut region, self.config.advices[0], 0)?;
                y.copy_advice(|| "word_add y", &mut region, self.config.advices[1], 0)?;
                let sum = x.value().zip(y.value()).map(|(&x, &y)| {
                    let sum = x + y;
                    let carry = F::from(sum.to_repr().as_ref()[4] as u64);
                    let ret = sum - carry * F::from(1 << 32);
                    (ret, carry)
                });
                let ret = region.assign_advice(
                    || "word_add ret",
                    self.config.advices[0],
                    1,
                    || sum.map(|sum| sum.0),
                )?;
                region.assign_advice(
                    || "word_add carry",
                    self.config.advices[1],
                    1,
                    || sum.map(|sum| sum.1),
                )?;
                Ok(ret)
            },
        )
    }
}

impl<F: PrimeField> Blake2sWord<F> {
    pub fn from_constant_u32(
        value: u32,
        layouter: &mut impl Layouter<F>,
        chip: &Blake2sChip<F>,
    ) -> Result<Self, Error> {
        let mut bytes = Vec::with_capacity(4);
        let mut word_bits = Vec::with_capacity(32);
        let mut tmp = value;
        for _ in 0..4 {
            let input_byte = tmp as u8;
            let byte = Blake2sByte::from_constant_u8(input_byte, layouter, &chip.config)?;
            bytes.push(byte.get_byte());
            word_bits.append(&mut byte.get_bits().to_vec());
            tmp >>= 8;
        }
        let word = assign_free_constant(
            layouter.namespace(|| "constant word"),
            chip.config.advices[0],
            F::from(value as u64),
        )?;
        chip.word_decompose(layouter.namespace(|| "word decompose"), &bytes, &word)?;
        Ok(Self {
            word,
            bits: word_bits.try_into().unwrap(),
        })
    }

    pub fn word_rotate(bits: &Vec<AssignedCell<F, F>>, by: usize) -> Vec<AssignedCell<F, F>> {
        assert!(bits.len() == 32);
        let by = by % 32;
        bits.iter()
            .skip(by)
            .chain(bits.iter())
            .take(32)
            .cloned()
            .collect()
    }

    pub fn shift(
        &self,
        by: usize,
        mut layouter: impl Layouter<F>,
        advice: Column<Advice>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let by = by % 32;
        let padding_zero = assign_free_constant(layouter.namespace(|| "zero"), advice, F::from(0))?;
        let old_bits = self.get_bits();
        Ok(old_bits
            .iter()
            .skip(by)
            .chain(Some(&padding_zero).into_iter().cycle())
            .take(32)
            .cloned()
            .collect())
    }

    pub fn get_bits(&self) -> &[AssignedCell<F, F>; 32] {
        &self.bits
    }

    pub fn get_word(&self) -> &AssignedCell<F, F> {
        &self.word
    }

    pub fn from_bits(
        chip: &Blake2sChip<F>,
        mut layouter: impl Layouter<F>,
        bits: Vec<AssignedCell<F, F>>,
    ) -> Result<Self, Error> {
        assert!(bits.len() == 32);
        let mut bytes = Vec::with_capacity(4);
        for bits in bits.chunks(8) {
            let bit_values: Value<Vec<_>> = bits.iter().map(|bit| bit.value()).collect();
            let byte_value = bit_values.map(|bits| {
                bits.into_iter()
                    .rev()
                    .fold(F::ZERO, |acc, bit| acc * F::from(2) + bit)
            });
            let byte = assign_free_advice(
                layouter.namespace(|| "assign byte"),
                chip.config.advices[8],
                byte_value,
            )?;
            chip.byte_decompose(layouter.namespace(|| "byte decompose"), bits, &byte)?;
            bytes.push(byte);
        }
        let word = {
            let byte_values: Value<Vec<_>> = bytes.iter().map(|byte| byte.value()).collect();
            let word_value = byte_values.map(|bytes| {
                bytes
                    .into_iter()
                    .rev()
                    .fold(F::ZERO, |acc, byte| acc * F::from(1 << 8) + byte)
            });
            assign_free_advice(
                layouter.namespace(|| "assign word"),
                chip.config.advices[8],
                word_value,
            )?
        };
        chip.word_decompose(layouter.namespace(|| "word decompose"), &bytes, &word)?;
        Ok(Self {
            word,
            bits: bits.try_into().unwrap(),
        })
    }

    pub fn from_word(
        chip: &Blake2sChip<F>,
        mut layouter: impl Layouter<F>,
        word: AssignedCell<F, F>,
    ) -> Result<Self, Error> {
        let mut bytes = Vec::with_capacity(4);
        let mut bits = Vec::with_capacity(32);
        for i in 0..4 {
            let byte_value = word.value().map(|v| v.to_repr().as_ref()[i]);
            let byte =
                Blake2sByte::from_u8(byte_value, layouter.namespace(|| "from_u8"), &chip.config)?;
            bits.append(&mut byte.get_bits().to_vec());
            bytes.push(byte.get_byte());
        }

        chip.word_decompose(layouter.namespace(|| "word decompose"), &bytes, &word)?;
        Ok(Self {
            word,
            bits: bits.try_into().unwrap(),
        })
    }
}

#[test]
fn test_blake2s_circuit() {
    use crate::{
        circuit::gadgets::assign_free_advice, constant::VP_COMMITMENT_PERSONALIZATION,
        vp_commitment::ValidityPredicateCommitment,
    };
    use halo2_proofs::{
        circuit::{floor_planner, Layouter, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pasta_curves::pallas;

    #[derive(Default)]
    struct MyCircuit {}

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = Blake2sConfig<pallas::Base>;
        type FloorPlanner = floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
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

            let constants = meta.fixed_column();
            meta.enable_constant(constants);
            Blake2sConfig::configure(meta, advices)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let vp = pallas::Base::one();
            let rcm = pallas::Base::one();
            let vp_var = assign_free_advice(
                layouter.namespace(|| "message one"),
                config.advices[0],
                Value::known(vp),
            )?;
            let rcm_var = assign_free_advice(
                layouter.namespace(|| "message two"),
                config.advices[0],
                Value::known(rcm),
            )?;

            let blake2s_chip = Blake2sChip::construct(config);
            let words_result = blake2s_chip.process(
                &mut layouter,
                &[vp_var, rcm_var],
                VP_COMMITMENT_PERSONALIZATION,
            )?;

            let expect_ret = ValidityPredicateCommitment::commit(&vp, &rcm);
            let expect_words_result: Vec<u32> = expect_ret
                .to_bytes()
                .chunks(4)
                .map(LittleEndian::read_u32)
                .collect();

            for (word, expect_word) in words_result.iter().zip(expect_words_result.into_iter()) {
                let expect_word_var = assign_free_advice(
                    layouter.namespace(|| "expected words"),
                    config.advices[0],
                    Value::known(pallas::Base::from(expect_word as u64)),
                )?;
                layouter.assign_region(
                    || "constrain result",
                    |mut region| {
                        region.constrain_equal(word.get_word().cell(), expect_word_var.cell())
                    },
                )?;
            }

            let expect_field_ret: [pallas::Base; 2] = expect_ret.to_public_inputs();
            let field_ret = blake2s_chip.encode_result(&mut layouter, &words_result)?;

            for (field, expect_field) in field_ret.iter().zip(expect_field_ret.into_iter()) {
                let expect_field_var = assign_free_advice(
                    layouter.namespace(|| "expected field"),
                    config.advices[0],
                    Value::known(expect_field),
                )?;
                layouter.assign_region(
                    || "constrain result",
                    |mut region| region.constrain_equal(field.cell(), expect_field_var.cell()),
                )?;
            }

            Ok(())
        }
    }

    let circuit = MyCircuit {};

    let prover = MockProver::run(14, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
