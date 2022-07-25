use crate::error::TaigaError;
use ark_ff::PrimeField;
use lazy_static::lazy_static;
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, Poseidon},
};

// ARITY: input number of hash
// WIDTH_3 = ARITY + 1
pub const WIDTH_3: usize = 3;
pub const WIDTH_5: usize = 5;
pub const WIDTH_9: usize = 9;
lazy_static! {
    pub static ref POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY2: PoseidonConstants<ark_bls12_381_new::Fr> =
        PoseidonConstants::generate::<WIDTH_3>();
    pub static ref POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY4: PoseidonConstants<ark_bls12_381_new::Fr> =
        PoseidonConstants::generate::<WIDTH_5>();

    // Hashes of bls12_377::BaseField are generated automatically, not tested yet.
    // Especially we need to check the round number generation from the paper.
    pub static ref POSEIDON_HASH_PARAM_BLS12_381_NEW_BASE_ARITY2: PoseidonConstants<ark_bls12_381_new::Fq> =
        PoseidonConstants::generate::<WIDTH_3>();
    pub static ref POSEIDON_HASH_PARAM_BLS12_381_NEW_BASE_ARITY4: PoseidonConstants<ark_bls12_381_new::Fq> =
        PoseidonConstants::generate::<WIDTH_5>();
}

/// A FieldHasher over prime field takes field elements as input and
/// outputs one field element. `native_hash_two` takes two field elements;
/// `native_hash` takes at most four field elements.
pub trait FieldHasher<F: PrimeField>: Clone {
    fn native_hash_two(&self, left: &F, right: &F) -> Result<F, TaigaError>;
    fn native_hash(&self, inputs: &[F]) -> Result<F, TaigaError>;
}

/// A FieldHasher implementation for Poseidon Hash.
impl<F: PrimeField> FieldHasher<F> for PoseidonConstants<F> {
    fn native_hash_two(&self, left: &F, right: &F) -> Result<F, TaigaError> {
        let mut poseidon = Poseidon::<(), NativeSpec<F, WIDTH_3>, WIDTH_3>::new(&mut (), self);
        poseidon.input(*left)?;
        poseidon.input(*right)?;
        Ok(poseidon.output_hash(&mut ()))
    }

    fn native_hash(&self, inputs: &[F]) -> Result<F, TaigaError> {
        assert!(inputs.len() < WIDTH_5);
        let mut poseidon = Poseidon::<(), NativeSpec<F, WIDTH_5>, WIDTH_5>::new(&mut (), self);
        // Default padding zero
        inputs.iter().for_each(|f| {
            poseidon.input(*f).unwrap();
        });
        Ok(poseidon.output_hash(&mut ()))
    }
}

#[test]
fn test_poseidon_circuit_example() {
    use ark_ec::PairingEngine;
    use ark_std::{test_rng, UniformRand};
    use plonk_hashing::poseidon::poseidon::{NativeSpec, PlonkSpec, Poseidon};
    type E = ark_bls12_381_new::Bls12_381New;
    type P = ark_ed_on_bls12_381_new::Parameters;
    type Fr = <E as PairingEngine>::Fr;
    use plonk_core::constraint_system::StandardComposer;

    let mut rng = test_rng();
    let mut poseidon_native = Poseidon::<(), NativeSpec<Fr, WIDTH_3>, WIDTH_3>::new(
        &mut (),
        &POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY2,
    );
    let inputs = (0..(WIDTH_3 - 1))
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    inputs.iter().for_each(|x| {
        let _ = poseidon_native.input(*x).unwrap();
    });
    let native_hash: Fr = poseidon_native.output_hash(&mut ());

    let mut c = StandardComposer::<Fr, P>::new();
    let inputs_var = inputs.iter().map(|x| c.add_input(*x)).collect::<Vec<_>>();
    let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(
        &mut c,
        &POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY2,
    );
    inputs_var.iter().for_each(|x| {
        let _ = poseidon_circuit.input(*x).unwrap();
    });
    let plonk_hash = poseidon_circuit.output_hash(&mut c);

    c.check_circuit_satisfied();

    let expected = c.add_input(native_hash);
    c.assert_equal(expected, plonk_hash);

    c.check_circuit_satisfied();
    println!(
        "circuit size for WIDTH_3 {} poseidon: {}",
        WIDTH_3,
        c.circuit_bound()
    )
}
