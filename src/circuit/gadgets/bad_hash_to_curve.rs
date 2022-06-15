use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::poseidon_hash_scalar_field::poseidon_hash_curve_scalar_field_gadget;
use crate::poseidon::WIDTH_3;
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
use plonk_core::prelude::{Point, StandardComposer};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, Poseidon},
};

pub fn bad_hash_to_curve_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    private_inputs: &Vec<CP::CurveScalarField>,
    _public_inputs: &Vec<CP::CurveScalarField>,
) -> Point<CP::InnerCurve> {
    // (bad) hash to curve:
    // 1. hash a scalar using poseidon
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mut poseidon = Poseidon::<
        (),
        NativeSpec<<CP as CircuitParameters>::CurveScalarField, WIDTH_3>,
        WIDTH_3,
    >::new(&mut (), &poseidon_hash_param_bls12_377_scalar_arity2);
    private_inputs.iter().for_each(|x| {
        poseidon.input(*x).unwrap();
    });
    let hash = poseidon.output_hash(&mut ());
    poseidon_hash_curve_scalar_field_gadget::<CP>(composer, private_inputs, &vec![hash]);
    // 2. multiply by the generator
    let generator = TEGroupAffine::prime_subgroup_generator();
    let scalar_variable = composer.add_input(hash);
    composer.fixed_base_scalar_mul(scalar_variable, generator)
}

#[test]
fn test_bad_hash_to_curve_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::crh;
    use crate::poseidon::WIDTH_3;
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;
    type F = <CP as CircuitParameters>::CurveScalarField;

    let mut rng = rand::thread_rng();
    let random_inputs = (0..(WIDTH_3 - 1))
        .map(|_| F::rand(&mut rng))
        .collect::<Vec<_>>();

    let hash = crh::<CP>(&random_inputs);

    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();

    let gadget_hash_variable =
        bad_hash_to_curve_gadget::<CP>(&mut composer, &random_inputs, &vec![]);
    composer.assert_equal_public_point(gadget_hash_variable, hash);
    composer.check_circuit_satisfied();
}
