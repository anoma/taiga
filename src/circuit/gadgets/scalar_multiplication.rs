use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{
    constraint_system::Variable,
    prelude::{Point, StandardComposer},
};

pub fn scalar_multiplication_gadget<F: PrimeField, P: TEModelParameters<BaseField = F>>(
    composer: &mut StandardComposer<F, P>,
    var_n: Variable,
) -> Point<P> {
    // simple circuit for the computaiton of [n] * a (and return the variable corresponding to b=[n]a).
    let (x, y) = P::AFFINE_GENERATOR_COEFFS;
    let generator = TEGroupAffine::<P>::new(x, y);
    composer.fixed_base_scalar_mul(var_n, generator)
}

#[test]
fn test_scalar_multiplication_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
    use ark_ec::TEModelParameters;

    type PC = <CP as CircuitParameters>::CurvePC;
    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    use ark_poly_commit::PolynomialCommitment;
    use plonk_core::proof_system::Prover;
    use plonk_core::proof_system::Verifier;
    use rand::rngs::OsRng;

    // Points
    let (x, y) = OP::AFFINE_GENERATOR_COEFFS;
    let generator = TEGroupAffine::<OP>::new(x, y);
    let scalar = Fq::from(3);
    let expected_point = generator + generator + generator;

    // public params
    let u_params = Opc::setup(512, None, &mut OsRng).unwrap();

    // Commit Key
    let (ck, vk) = Opc::trim(&u_params, 512, 0, None).unwrap();

    // prover
    let mut prover: Prover<Fq, OP, Opc> = Prover::new(b"demo");

    // gadget
    let composer_prover = prover.mut_cs();
    let var_n = composer_prover.add_input(scalar);
    let point = composer_prover.fixed_base_scalar_mul(var_n, generator);
    composer_prover.assert_equal_public_point(point, expected_point);
    composer_prover.check_circuit_satisfied();

    // Preprocess circuit
    prover.preprocess(&ck).unwrap();

    let public_inputs = prover.cs.get_pi().clone();

    let proof = prover.prove(&ck).unwrap();

    // Verifier
    let mut verifier = Verifier::<Fq, OP, Opc>::new(b"demo");

    // Verifier gadget
    let composer_verifier = verifier.mut_cs();
    let var_n = composer_verifier.add_input(scalar);
    let point = composer_verifier.fixed_base_scalar_mul(var_n, generator);
    composer_verifier.assert_equal_public_point(point, expected_point);
    composer_verifier.check_circuit_satisfied();

    // // Preprocess
    verifier.preprocess(&ck).unwrap();

    assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());
}
