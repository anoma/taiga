use crate::circuit::circuit_parameters::CircuitParameters;
use plonk_core::prelude::{Point, StandardComposer};

pub fn point_addition_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    var_a: Point<CP::InnerCurve>,
    var_b: Point<CP::InnerCurve>,
) -> Point<CP::InnerCurve> {
    // simple circuit for the computaiton of a+b (and return the variable corresponding to c=a+b).
    composer.point_addition_gate(var_a, var_b)
}

#[test]
fn test_point_addition_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use ark_ec::TEModelParameters;
    use plonk_core::constraint_system::StandardComposer;

    use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
    type C = <CP as CircuitParameters>::InnerCurve;

    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();

    let (x, y) = C::AFFINE_GENERATOR_COEFFS;
    let generator = TEGroupAffine::<C>::new(x, y);
    let x_var = composer.add_input(x);
    let y_var = composer.add_input(y);
    let expected_point = generator + generator;
    let point_a = Point::new(x_var, y_var);
    let point_b = Point::new(x_var, y_var);

    let point = composer.point_addition_gate(point_a, point_b);

    composer.assert_equal_public_point(point, expected_point);
    composer.check_circuit_satisfied();
}
