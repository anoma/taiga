use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::prelude::{Point, StandardComposer};

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

    type PC = <CP as CircuitParameters>::CurvePC;
    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;

    // Points
    let (x, y) = P::AFFINE_GENERATOR_COEFFS;
    let generator = TEGroupAffine::<P>::new(x, y);
    let expected_point = generator + generator;

    // gadget
    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();
    let x_var = composer.add_input(x);
    let y_var = composer.add_input(y);
    let point_a: Point<P> = Point::new(x_var, y_var);
    let point_b: Point<P> = Point::new(x_var, y_var);
    let point = composer.point_addition_gate(point_a, point_b);
    composer.assert_equal_public_point(point, expected_point);
    composer.check_circuit_satisfied();
}
