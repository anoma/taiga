use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{
    circuit::Circuit,
    prelude::{Point, StandardComposer},
};

pub fn point_addition_gadget<F: PrimeField, P: TEModelParameters<BaseField = F>>(
    composer: &mut StandardComposer<F, P>,
    var_a: Point<P>,
    var_b: Point<P>,
) -> Point<P> {
    // simple circuit for the computaiton of a+b (and return the variable corresponding to c=a+b).
    composer.point_addition_gate(var_a, var_b)
}

#[test]
fn test_point_addition_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
    use ark_ec::TEModelParameters;

    type OPC = <CP as CircuitParameters>::OuterCurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    use ark_poly_commit::PolynomialCommitment;
    use plonk_core::proof_system::Prover;
    use plonk_core::proof_system::Verifier;
    use rand::rngs::OsRng;

    // Points
    let (x, y) = OP::AFFINE_GENERATOR_COEFFS;
    let generator = TEGroupAffine::<OP>::new(x, y);
    let expected_point = generator + generator;

    // public params
    let u_params = OPC::setup(2 * 30, None, &mut OsRng).unwrap();

    // Commit Key
    let (ck, vk) = OPC::trim(&u_params, 2 * 20, 0, None).unwrap();

    // prover
    let mut prover: Prover<Fq, OP, OPC> = Prover::new(b"demo");

    // gadget
    let composer_prover = prover.mut_cs();
    let x_var = composer_prover.add_input(x);
    let y_var = composer_prover.add_input(y);
    let point_a: Point<OP> = Point::new(x_var, y_var);
    let point_b: Point<OP> = Point::new(x_var, y_var);
    let point = composer_prover.point_addition_gate(point_a, point_b);
    composer_prover.assert_equal_public_point(point, expected_point);
    composer_prover.check_circuit_satisfied();

    // Preprocess circuit
    prover.preprocess(&ck).unwrap();

    let public_inputs = prover.cs.get_pi().clone();

    let proof = prover.prove(&ck).unwrap();

    // Verifier
    let mut verifier = Verifier::<Fq, OP, OPC>::new(b"demo");

    // Verifier gadget
    let composer_verifier = verifier.mut_cs();
    let x_var = composer_verifier.add_input(x);
    let y_var = composer_verifier.add_input(y);
    let point_a: Point<OP> = Point::new(x_var, y_var);
    let point_b: Point<OP> = Point::new(x_var, y_var);
    let point = composer_verifier.point_addition_gate(point_a, point_b);
    composer_verifier.assert_equal_public_point(point, expected_point);
    composer_verifier.check_circuit_satisfied();

    // // Preprocess
    verifier.preprocess(&ck).unwrap();

    assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());
}
