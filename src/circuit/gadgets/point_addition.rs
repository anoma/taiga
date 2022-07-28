use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::prelude::{Point, StandardComposer};

pub fn point_addition_gadget<F: PrimeField, P: TEModelParameters<BaseField = F>>(
    composer: &mut StandardComposer<F, P>,
    var_a: Point<P>,
    var_b: Point<P>,
) -> Point<P> {
    // simple circuit for the computaiton of a+b (and return the variable corresponding to c=a+b).
    // composer.point_addition_gate(var_a, var_b)
    let zero = composer.zero_var();
    let x1 = *var_a.x();
    let y1 = *var_a.y();

    let x2 = *var_b.x();
    let y2 = *var_b.y();

    // x1 * y2
    let x1_y2 = composer.arithmetic_gate(|gate| gate.mul(F::one()).witness(x1, y2, None));
    // y1 * x2
    let y1_x2 = composer.arithmetic_gate(|gate| gate.mul(F::one()).witness(y1, x2, None));
    // y1 * y2
    let y1_y2 = composer.arithmetic_gate(|gate| gate.mul(F::one()).witness(y1, y2, None));
    // x1 * x2
    let x1_x2 = composer.arithmetic_gate(|gate| gate.mul(F::one()).witness(x1, x2, None));
    // d x1x2 * y1y2
    let d_x1_x2_y1_y2 =
        composer.arithmetic_gate(|gate| gate.mul(P::COEFF_D).witness(x1_x2, y1_y2, None));

    // x1y2 + y1x2
    let x_numerator =
        composer.arithmetic_gate(|gate| gate.witness(x1_y2, y1_x2, None).add(F::one(), F::one()));

    // y1y2 - a * x1x2
    let y_numerator = composer
        .arithmetic_gate(|gate| gate.witness(y1_y2, x1_x2, None).add(F::one(), -P::COEFF_A));

    // 1 + dx1x2y1y2
    let x_denominator = composer.arithmetic_gate(|gate| {
        gate.witness(d_x1_x2_y1_y2, zero, None)
            .add(F::one(), F::zero())
            .constant(F::one())
    });

    // Compute the inverse
    let inv_x_denom = composer.get_value(&x_denominator).inverse().unwrap();
    let inv_x_denom = composer.add_input(inv_x_denom);

    // Assert that we actually have the inverse
    // inv_x * x = 1
    composer.arithmetic_gate(|gate| {
        gate.witness(x_denominator, inv_x_denom, Some(zero))
            .mul(F::one())
            .constant(-F::one())
    });

    // 1 - dx1x2y1y2
    let y_denominator = composer.arithmetic_gate(|gate| {
        gate.witness(d_x1_x2_y1_y2, zero, None)
            .add(-F::one(), F::zero())
            .constant(F::one())
    });

    let inv_y_denom = composer.get_value(&y_denominator).inverse().unwrap();

    let inv_y_denom = composer.add_input(inv_y_denom);
    // Assert that we actually have the inverse
    // inv_y * y = 1
    composer.arithmetic_gate(|gate| {
        gate.mul(F::one())
            .witness(y_denominator, inv_y_denom, Some(zero))
            .constant(-F::one())
    });

    // We can now use the inverses

    let x_3 =
        composer.arithmetic_gate(|gate| gate.mul(F::one()).witness(inv_x_denom, x_numerator, None));

    let y_3 =
        composer.arithmetic_gate(|gate| gate.mul(F::one()).witness(inv_y_denom, y_numerator, None));

    Point::new(x_3, y_3)
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
