use crate::poseidon::WIDTH_3;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{constraint_system::Variable, prelude::StandardComposer};
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
    _public_inputs: &[F],
) -> Variable {
    // no public input here
    // private_inputs are the inputs for the Poseidon hash
    let inputs_var = private_inputs
        .iter()
        .map(|x| composer.add_input(*x))
        .collect::<Vec<_>>();

    // params for poseidon TODO make it const
    let poseidon_hash_param_bls12_381_new_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(
        composer,
        &poseidon_hash_param_bls12_381_new_scalar_arity2,
    );
    inputs_var.iter().for_each(|x| {
        let _ = poseidon_circuit.input(*x).unwrap();
    });
    poseidon_circuit.output_hash(composer)
}

#[test]
fn test_poseidon_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::WIDTH_3;
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;
    use plonk_hashing::poseidon::constants::PoseidonConstants;
    use plonk_hashing::poseidon::poseidon::NativeSpec;
    use plonk_hashing::poseidon::poseidon::Poseidon;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;

    let mut rng = rand::thread_rng();
    let ω = (0..(WIDTH_3 - 1))
        .map(|_| F::rand(&mut rng))
        .collect::<Vec<_>>();
    let poseidon_hash_param_bls12_381_new_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mut poseidon = Poseidon::<(), NativeSpec<F, WIDTH_3>, WIDTH_3>::new(
        &mut (),
        &poseidon_hash_param_bls12_381_new_scalar_arity2,
    );
    ω.iter().for_each(|x| {
        poseidon.input(*x).unwrap();
    });
    let hash = poseidon.output_hash(&mut ());
    let mut composer = StandardComposer::<F, P>::new();
    let native_hash_variable = composer.add_public_input_variable(hash);
    let gadget_hash_variable =
        poseidon_hash_curve_scalar_field_gadget::<F, P>(&mut composer, &ω, &[hash]);
    composer.assert_equal(native_hash_variable, gadget_hash_variable);
    composer.check_circuit_satisfied();
}
