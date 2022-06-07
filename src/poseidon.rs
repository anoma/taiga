use ark_ff::PrimeField;
use lazy_static::lazy_static;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use plonk_hashing::poseidon::poseidon::{NativeSpec, Poseidon};
use plonk_hashing::poseidon::PoseidonError;

// ARITY: input number of hash
// WIDTH_3 = ARITY + 1
pub const WIDTH_3: usize = 3;
pub const WIDTH_5: usize = 5;
lazy_static! {
    pub static ref POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2: PoseidonConstants<ark_bls12_377::Fr> =
        PoseidonConstants::generate::<WIDTH_3>();
    pub static ref POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4: PoseidonConstants<ark_bls12_377::Fr> =
        PoseidonConstants::generate::<WIDTH_5>();

    // Hashes of bls12_377::BaseField are generated automatically, not tested yet.
    // Especially we need to check the round number generation from the paper.
    pub static ref POSEIDON_HASH_PARAM_BLS12_377_BASE_ARITY2: PoseidonConstants<ark_bls12_377::Fq> =
        PoseidonConstants::generate::<WIDTH_3>();
    pub static ref POSEIDON_HASH_PARAM_BLS12_377_BASE_ARITY4: PoseidonConstants<ark_bls12_377::Fq> =
        PoseidonConstants::generate::<WIDTH_5>();
}

pub trait BinaryHasher<F: PrimeField> {
    fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError>;
}

impl<F: PrimeField> BinaryHasher<F> for PoseidonConstants<F> {
    fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError> {
        let mut poseidon = Poseidon::<(), NativeSpec<F, WIDTH_3>, WIDTH_3>::new(&mut (), &self);
        poseidon.input(*left)?;
        poseidon.input(*right)?;
        Ok(poseidon.output_hash(&mut ()))
    }
}

#[test]
fn test_poseidon_circuit_example() {
    use ark_ec::PairingEngine;
    use ark_std::{test_rng, UniformRand};
    use plonk_hashing::poseidon::poseidon::{NativeSpec, PlonkSpec, Poseidon};
    type E = ark_bls12_377::Bls12_377;
    type P = ark_ed_on_bls12_377::EdwardsParameters;
    type Fr = <E as PairingEngine>::Fr;
    use plonk_core::constraint_system::StandardComposer;

    let mut rng = test_rng();
    let mut poseidon_native = Poseidon::<(), NativeSpec<Fr, WIDTH_3>, WIDTH_3>::new(
        &mut (),
        &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
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
        &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
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
