use crate::poseidon::WIDTH_3;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::prelude::StandardComposer;
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{PlonkSpec, Poseidon},
};

pub fn poseidon_hash_curve_scalar_field_gadget<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
>(
    composer: &mut StandardComposer<F, P>,
    private_inputs: &[F],
    public_inputs: &[F],
) {
    // no public input here
    // private_inputs are the inputs for the Poseidon hash
    let inputs_var = private_inputs
        .iter()
        .map(|x| composer.add_input(*x))
        .collect::<Vec<_>>();

    // params for poseidon TODO make it const
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(
        composer,
        &poseidon_hash_param_bls12_377_scalar_arity2,
    );
    inputs_var.iter().for_each(|x| {
        let _ = poseidon_circuit.input(*x).unwrap();
    });
    let hash_out_1 = poseidon_circuit.output_hash(composer);
    let hash_out_2 = composer.add_input(public_inputs[0]);
    let _ = composer.assert_equal(hash_out_1, hash_out_2);
}

#[test]
fn test_proof_verify() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::circuit::validity_predicate::ValidityPredicate;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::UniformRand;
    use plonk_hashing::poseidon::poseidon::NativeSpec;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type InnerC = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;

    // hash some random value
    let mut rng = rand::thread_rng();
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mut poseidon_native = Poseidon::<(), NativeSpec<F, WIDTH_3>, WIDTH_3>::new(
        &mut (),
        &poseidon_hash_param_bls12_377_scalar_arity2,
    );
    let inputs = (0..(WIDTH_3 - 1))
        .map(|_| F::rand(&mut rng))
        .collect::<Vec<_>>();
    inputs.iter().for_each(|x| {
        let _ = poseidon_native.input(*x).unwrap();
    });
    let native_hash: F = poseidon_native.output_hash(&mut ());

    // create a setup for a ZK proof using KZG
    let setup = PC::setup(1 << 9, None, &mut rng).unwrap();

    // create the VP
    let vp = ValidityPredicate::<CP>::new(
        &setup,
        poseidon_hash_curve_scalar_field_gadget::<F, InnerC>,
        &inputs,
        &[native_hash],
        false, // do you want to blind?
        &mut rng,
    );

    // verify the VP
    vp.verify();
}
