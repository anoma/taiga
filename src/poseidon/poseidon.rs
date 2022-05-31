//! optimized poseidon

use crate::poseidon::{
    constants::PoseidonConstants, matrix::Matrix, mds::SparseMatrix, PoseidonError,
};
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use derivative::Derivative;
use plonk_core::{constraint_system::StandardComposer, prelude};
use std::{fmt::Debug, marker::PhantomData};

// TODO: reduce duplicate code with `poseidon_ref`
pub trait PoseidonSpec<COM, const WIDTH: usize> {
    type Field: Debug + Clone;
    type ParameterField: PrimeField;

    fn output_hash(
        c: &mut COM,
        constants_offset: &mut usize,
        current_round: &mut usize,
        elements: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
    ) -> Self::Field {
        Self::add_round_constants(c, elements, constants, constants_offset);

        for _ in 0..constants.half_full_rounds {
            Self::full_round(
                c,
                constants,
                current_round,
                constants_offset,
                false,
                elements,
            )
        }

        for _ in 0..constants.partial_rounds {
            Self::partial_round(c, constants, current_round, constants_offset, elements);
        }

        // All but last full round
        for _ in 1..constants.half_full_rounds {
            Self::full_round(
                c,
                constants,
                current_round,
                constants_offset,
                false,
                elements,
            );
        }
        Self::full_round(
            c,
            constants,
            current_round,
            constants_offset,
            true,
            elements,
        );

        assert_eq!(
            *constants_offset,
            constants.compressed_round_constants.len(),
            "Constants consumed ({}) must equal preprocessed constants provided ({}).",
            constants_offset,
            constants.compressed_round_constants.len()
        );

        elements[1].clone()
    }

    fn full_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        const_offset: &mut usize,
        last_round: bool,
        state: &mut [Self::Field; WIDTH],
    ) {
        let to_take = WIDTH;
        let post_round_keys = constants
            .compressed_round_constants
            .iter()
            .skip(*const_offset)
            .take(to_take);

        if !last_round {
            let needed = *const_offset + to_take;
            assert!(
                needed <= constants.compressed_round_constants.len(),
                "Not enough preprocessed round constants ({}), need {}.",
                constants.compressed_round_constants.len(),
                needed
            );
        }

        state.iter_mut().zip(post_round_keys).for_each(|(l, post)| {
            // Be explicit that no round key is added after last round of S-boxes.
            let post_key = if last_round {
                panic!(
                    "Trying to skip last full round, but there is a key here! ({:?})",
                    post
                );
            } else {
                Some(post.clone())
            };
            *l = Self::quintic_s_box(c, l.clone(), None, post_key);
        });

        if last_round {
            state
                .iter_mut()
                .for_each(|l| *l = Self::quintic_s_box(c, l.clone(), None, None))
        } else {
            *const_offset += to_take;
        }
        Self::round_product_mds(c, constants, current_round, state);
    }

    fn partial_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        const_offset: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let post_round_key = constants.compressed_round_constants[*const_offset];

        state[0] = Self::quintic_s_box(c, state[0].clone(), None, Some(post_round_key));
        *const_offset += 1;

        Self::round_product_mds(c, constants, current_round, state);
    }

    fn add_round_constants(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
        const_offset: &mut usize,
    ) {
        for (element, round_constant) in state.iter_mut().zip(
            constants
                .compressed_round_constants
                .iter()
                .skip(*const_offset),
        ) {
            *element = Self::addi(c, element, round_constant);
        }
        *const_offset += WIDTH;
    }

    fn round_product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let full_half = constants.half_full_rounds;
        let sparse_offset = full_half - 1;
        if *current_round == sparse_offset {
            Self::product_mds_with_matrix(c, state, &constants.pre_sparse_matrix)
        } else {
            if (*current_round > sparse_offset)
                && (*current_round < full_half + constants.partial_rounds)
            {
                let index = *current_round - sparse_offset - 1;
                let sparse_matrix = &constants.sparse_matrixes[index];

                Self::product_mds_with_sparse_matrix(c, state, sparse_matrix)
            } else {
                Self::product_mds(c, constants, state)
            }
        };

        *current_round += 1;
    }

    fn product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        state: &mut [Self::Field; WIDTH],
    ) {
        Self::product_mds_with_matrix(c, state, &constants.mds_matrices.m)
    }

    fn linear_combination(
        c: &mut COM,
        state: &[Self::Field; WIDTH],
        coeff: impl IntoIterator<Item = Self::ParameterField>,
    ) -> Self::Field {
        state.iter().zip(coeff).fold(Self::zero(c), |acc, (x, y)| {
            let tmp = Self::muli(c, x, &y);
            Self::add(c, &tmp, &acc)
        })
    }

    /// compute state @ Mat where `state` is a row vector
    fn product_mds_with_matrix(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        matrix: &Matrix<Self::ParameterField>,
    ) {
        let mut result = Self::zeros::<WIDTH>(c);
        for (col_index, val) in result.iter_mut().enumerate() {
            // for (i, row) in matrix.iter_rows().enumerate() {
            //     // *val += row[j] * state[i];
            //     let tmp = Self::muli(c, &state[i], &row[j]);
            //     *val = Self::add(c, val, &tmp);
            // }
            *val = Self::linear_combination(c, state, matrix.column(col_index).cloned());
        }

        *state = result;
    }

    fn product_mds_with_sparse_matrix(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        matrix: &SparseMatrix<Self::ParameterField>,
    ) {
        let mut result = Self::zeros::<WIDTH>(c);

        // First column is dense.
        // for (i, val) in matrix.w_hat.iter().enumerate() {
        //     // result[0] += w_hat[i] * state[i];
        //     let tmp = Self::muli(c, &state[i], &val);
        //     result[0] = Self::add(c, &result[0], &tmp);
        // }
        result[0] = Self::linear_combination(c, state, matrix.w_hat.iter().cloned());

        for (j, val) in result.iter_mut().enumerate().skip(1) {
            // for each j, result[j] = state[j] + state[0] * v_rest[j-1]

            // Except for first row/column, diagonals are one.
            *val = Self::add(c, val, &state[j]);
            // // First row is dense.
            let tmp = Self::muli(c, &state[0], &matrix.v_rest[j - 1]);
            *val = Self::add(c, val, &tmp);
        }
        *state = result;
    }

    /// return (x + pre_add)^5 + post_add
    fn quintic_s_box(
        c: &mut COM,
        x: Self::Field,
        pre_add: Option<Self::ParameterField>,
        post_add: Option<Self::ParameterField>,
    ) -> Self::Field {
        let mut tmp = match pre_add {
            Some(a) => Self::addi(c, &x, &a),
            None => x.clone(),
        };
        tmp = Self::power_of_5(c, &tmp);
        match post_add {
            Some(a) => Self::addi(c, &tmp, &a),
            None => tmp,
        }
    }

    fn power_of_5(c: &mut COM, x: &Self::Field) -> Self::Field {
        let mut tmp = Self::mul(c, x, x); // x^2
        tmp = Self::mul(c, &tmp, &tmp); // x^4
        Self::mul(c, &tmp, x) // x^5
    }

    fn alloc(c: &mut COM, v: Self::ParameterField) -> Self::Field;
    fn zeros<const W: usize>(c: &mut COM) -> [Self::Field; W];
    fn zero(c: &mut COM) -> Self::Field {
        Self::zeros::<1>(c)[0].clone()
    }
    fn add(c: &mut COM, x: &Self::Field, y: &Self::Field) -> Self::Field;
    fn addi(c: &mut COM, a: &Self::Field, b: &Self::ParameterField) -> Self::Field;
    fn mul(c: &mut COM, x: &Self::Field, y: &Self::Field) -> Self::Field;
    fn muli(c: &mut COM, x: &Self::Field, y: &Self::ParameterField) -> Self::Field;
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct Poseidon<'a, COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize>
where
    S: ?Sized,
{
    pub(crate) constants_offset: usize,
    pub(crate) current_round: usize,
    pub elements: [S::Field; WIDTH],
    pos: usize,
    pub(crate) constants: &'a PoseidonConstants<S::ParameterField>,
}

impl<'a, COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> Clone for Poseidon<'a, COM, S, WIDTH>
where
    S: ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            constants_offset: self.constants_offset,
            current_round: self.current_round,
            elements: self.elements.clone(),
            pos: self.pos,
            constants: self.constants,
        }
    }
}

impl<'a, COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> Poseidon<'a, COM, S, WIDTH>
where
    S: ?Sized,
{
    pub fn new(c: &mut COM, constants: &'a PoseidonConstants<S::ParameterField>) -> Self {
        let mut elements = S::zeros(c);
        elements[0] = S::alloc(c, constants.domain_tag);
        Poseidon {
            constants_offset: 0,
            current_round: 0,
            elements,
            pos: 1,
            constants,
        }
    }

    pub fn arity(&self) -> usize {
        WIDTH - 1
    }

    pub fn reset(&mut self, c: &mut COM) {
        self.constants_offset = 0;
        self.current_round = 0;
        self.elements[1..].iter_mut().for_each(|l| *l = S::zero(c));
        self.elements[0] = S::alloc(c, self.constants.domain_tag);
        self.pos = 1;
    }

    /// input one field element to Poseidon. Return the position of the element
    /// in state.
    pub fn input(&mut self, input: S::Field) -> Result<usize, PoseidonError> {
        // Cannot input more elements than the defined constant width
        if self.pos >= WIDTH {
            return Err(PoseidonError::FullBuffer);
        }

        // Set current element, and increase the pointer
        self.elements[self.pos] = input;
        self.pos += 1;

        Ok(self.pos - 1)
    }

    /// Hash an array of ARITY-many elements.  The size of elements could be
    /// specified as WIDTH - 1 when const generic expressions are allowed.
    /// Function will panic if elements does not have length ARITY.
    pub fn output_hash(&mut self, c: &mut COM) -> S::Field {
        S::output_hash(
            c,
            &mut self.constants_offset,
            &mut self.current_round,
            &mut self.elements,
            &self.constants,
        )
    }
}

pub struct NativeSpec<F: PrimeField, const WIDTH: usize> {
    _field: PhantomData<F>,
}

impl<F: PrimeField, const WIDTH: usize> PoseidonSpec<(), WIDTH> for NativeSpec<F, WIDTH> {
    type Field = F;
    type ParameterField = F;

    fn alloc(_c: &mut (), v: Self::ParameterField) -> Self::Field {
        v
    }

    fn zeros<const W: usize>(_c: &mut ()) -> [Self::Field; W] {
        [F::zero(); W]
    }

    fn add(_c: &mut (), x: &Self::Field, y: &Self::Field) -> Self::Field {
        *x + *y
    }

    fn addi(_c: &mut (), a: &Self::Field, b: &Self::ParameterField) -> Self::Field {
        *a + *b
    }

    fn mul(_c: &mut (), x: &Self::Field, y: &Self::Field) -> Self::Field {
        *x * *y
    }

    fn muli(_c: &mut (), x: &Self::Field, y: &Self::ParameterField) -> Self::Field {
        *x * *y
    }
}

pub struct PlonkSpec<const WIDTH: usize>;

impl<F, P, const WIDTH: usize> PoseidonSpec<prelude::StandardComposer<F, P>, WIDTH>
    for PlonkSpec<WIDTH>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    type Field = prelude::Variable;
    type ParameterField = F;

    fn alloc(c: &mut StandardComposer<F, P>, v: Self::ParameterField) -> Self::Field {
        c.add_input(v)
    }

    fn zeros<const W: usize>(c: &mut StandardComposer<F, P>) -> [Self::Field; W] {
        [c.zero_var(); W]
    }

    fn add(c: &mut StandardComposer<F, P>, x: &Self::Field, y: &Self::Field) -> Self::Field {
        c.arithmetic_gate(|g| g.witness(*x, *y, None).add(F::one(), F::one()))
    }

    fn addi(
        c: &mut StandardComposer<F, P>,
        a: &Self::Field,
        b: &Self::ParameterField,
    ) -> Self::Field {
        let zero = c.zero_var();
        c.arithmetic_gate(|g| {
            g.witness(*a, zero, None)
                .add(F::one(), F::zero())
                .constant(*b)
        })
    }

    fn mul(c: &mut StandardComposer<F, P>, x: &Self::Field, y: &Self::Field) -> Self::Field {
        c.arithmetic_gate(|q| q.witness(*x, *y, None).mul(F::one()))
    }

    fn muli(
        c: &mut StandardComposer<F, P>,
        x: &Self::Field,
        y: &Self::ParameterField,
    ) -> Self::Field {
        let zero = c.zero_var();
        c.arithmetic_gate(|g| g.witness(*x, zero, None).add(*y, F::zero()))
    }

    #[cfg(not(feature = "no-optimize"))]
    fn quintic_s_box(
        c: &mut StandardComposer<F, P>,
        x: Self::Field,
        pre_add: Option<Self::ParameterField>,
        post_add: Option<Self::ParameterField>,
    ) -> Self::Field {
        match (pre_add, post_add) {
            (None, None) => Self::power_of_5(c, &x),
            (Some(_), None) => {
                unreachable!("currently no one is using this")
            }
            (None, Some(post_add)) => {
                let x_2 = Self::mul(c, &x, &x);
                let x_4 = Self::mul(c, &x_2, &x_2);
                c.arithmetic_gate(|g| g.witness(x_4, x, None).mul(F::one()).constant(post_add))
            }
            (Some(_), Some(_)) => {
                /*
                P = (x + a)^5 + b
                = x^5 + 5x^4a + 10x^3a^2 + 10x^2a^3 + 5xa^4 + a^5 + b

                we first compute x^2, x^4 -> 2 constraints
                P_a = 10a^2*x^2*x 10*x^2*a^3 + 5xa^4 + a^5 + b    -> 1 constraint
                P = x^4 * x + 5x^4a + P_a -> 1 constraint

                 we can see that the constraints counts are same as naive one...
                */
                unreachable!("currently no one is using this")
            }
        }
    }

    #[cfg(not(feature = "no-optimize"))]
    fn linear_combination(
        c: &mut StandardComposer<F, P>,
        state: &[Self::Field; WIDTH],
        coeff: impl IntoIterator<Item = Self::ParameterField>,
    ) -> Self::Field {
        // some specialization on width
        let coeffs = coeff.into_iter().collect::<Vec<_>>();
        match WIDTH {
            3 => c.arithmetic_gate(|g| {
                g.witness(state[0], state[1], None)
                    .add(coeffs[0], coeffs[1])
                    .fan_in_3(coeffs[2], state[2])
            }),
            _ => state.iter().zip(coeffs).fold(Self::zero(c), |acc, (x, y)| {
                let tmp = Self::muli(c, x, &y);
                Self::add(c, &tmp, &acc)
            }),
        }
    }

    #[cfg(not(feature = "no-optimize"))]
    fn product_mds_with_sparse_matrix(
        c: &mut StandardComposer<F, P>,
        state: &mut [Self::Field; WIDTH],
        matrix: &SparseMatrix<Self::ParameterField>,
    ) {
        let mut result = Self::zeros::<WIDTH>(c);

        result[0] = Self::linear_combination(c, state, matrix.w_hat.iter().cloned());
        for (j, val) in result.iter_mut().enumerate().skip(1) {
            // for each j, result[j] = state[j] + state[0] * v_rest[j-1]
            *val = c.arithmetic_gate(|g| {
                g.witness(state[0], state[j], None)
                    .add(matrix.v_rest[j - 1], F::one())
            });
        }
        *state = result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::{
        constants::{
            POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
            POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4,
        },
        poseidon_ref::{NativeSpecRef, PoseidonRef},
    };

    use ark_ec::PairingEngine;
    use ark_std::{test_rng, UniformRand};

    type E = ark_bls12_377::Bls12_377;
    type P = ark_ed_on_bls12_377::EdwardsParameters;
    type Fr = <E as PairingEngine>::Fr;

    #[test]
    // because poseidon_ref matches reference implementation, if optimized poseidon
    // matches poseidon_ref, then it also matches reference implementation.
    fn compare_with_poseidon_ref() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4.clone();
        let mut poseidon = PoseidonRef::<(), NativeSpecRef<Fr>, WIDTH>::new(&mut (), param.clone());
        let inputs = (0..ARITY).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        inputs.iter().for_each(|x| {
            let _ = poseidon.input(*x).unwrap();
        });
        let hash_expected: Fr = poseidon.output_hash(&mut ());

        let mut poseidon_optimized =
            Poseidon::<(), NativeSpec<Fr, WIDTH>, WIDTH>::new(&mut (), &param);
        inputs.iter().for_each(|x| {
            let _ = poseidon_optimized.input(*x).unwrap();
        });
        let hash_actual = poseidon_optimized.output_hash(&mut ());

        assert_eq!(hash_expected, hash_actual);
    }

    #[test]
    fn reset() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4.clone();
        let inputs = (0..ARITY).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let mut poseidon_optimized =
            Poseidon::<(), NativeSpec<Fr, WIDTH>, WIDTH>::new(&mut (), &param);
        inputs.iter().for_each(|x| {
            let _ = poseidon_optimized.input(*x).unwrap();
        });
        let _ = poseidon_optimized.output_hash(&mut ());
        poseidon_optimized.reset(&mut ());

        let default = Poseidon::<(), NativeSpec<Fr, WIDTH>, WIDTH>::new(&mut (), &param);
        assert_eq!(default.pos, poseidon_optimized.pos);
        assert_eq!(default.elements, poseidon_optimized.elements);
        assert_eq!(
            default.constants_offset,
            poseidon_optimized.constants_offset
        );
    }

    #[test]
    // poseidon should output something if num_inputs = arity
    fn check_plonk_spec_with_native() {
        if cfg!(feature = "no-optimize") {
            println!("WARNING: plonk-specific optimization is disabled");
        }

        const ARITY: usize = 2;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2.clone();
        let mut poseidon_native =
            Poseidon::<(), NativeSpec<Fr, WIDTH>, WIDTH>::new(&mut (), &param);
        let inputs = (0..ARITY).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        inputs.iter().for_each(|x| {
            let _ = poseidon_native.input(*x).unwrap();
        });
        let native_hash: Fr = poseidon_native.output_hash(&mut ());

        let mut c = StandardComposer::<Fr, P>::new();
        let inputs_var = inputs.iter().map(|x| c.add_input(*x)).collect::<Vec<_>>();
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH>, WIDTH>::new(&mut c, &param);
        inputs_var.iter().for_each(|x| {
            let _ = poseidon_circuit.input(*x).unwrap();
        });
        let plonk_hash = poseidon_circuit.output_hash(&mut c);

        // TODO: update plonk and add the test
        // c.check_circuit_satisfied();

        let expected = c.add_input(native_hash);
        c.assert_equal(expected, plonk_hash);

        // TODO: update plonk and add the test
        // c.check_circuit_satisfied();
        println!(
            "circuit size for WIDTH {} poseidon: {}",
            WIDTH,
            c.circuit_bound()
        )
    }

    #[test]
    #[should_panic]
    // poseidon should output something if num_inputs > arity
    fn sanity_test_failure() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4.clone();
        let mut poseidon = Poseidon::<(), NativeSpec<Fr, WIDTH>, WIDTH>::new(&mut (), &param);
        (0..(ARITY + 1)).for_each(|_| {
            let _ = poseidon.input(Fr::rand(&mut rng)).unwrap();
        });
        let _ = poseidon.output_hash(&mut ());
    }
}
