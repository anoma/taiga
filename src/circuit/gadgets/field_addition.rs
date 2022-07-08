use crate::circuit::circuit_parameters::CircuitParameters;
use ark_ff::One;
use plonk_core::{constraint_system::Variable, prelude::StandardComposer};

pub fn field_addition_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    var_a: Variable,
    var_b: Variable,
    c: CP::CurveScalarField,
) {
    // simple circuit that checks that a + b == c
    let one = CP::CurveScalarField::one();
    let var_zero = composer.zero_var();
    // Make first constraint a + b = c (as public input)
    composer.arithmetic_gate(|gate| {
        gate.witness(var_a, var_b, Some(var_zero))
            .add(one, one)
            .pi(-c)
    });
}

#[test]
fn test_field_addition_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use plonk_core::constraint_system::StandardComposer;

    let a = <CP as CircuitParameters>::CurveScalarField::from(2u64);
    let b = <CP as CircuitParameters>::CurveScalarField::from(1u64);
    let c = <CP as CircuitParameters>::CurveScalarField::from(3u64);
    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();
    let var_a = composer.add_input(a);
    let var_b = composer.add_input(b);
    field_addition_gadget::<CP>(&mut composer, var_a, var_b, c);
    composer.check_circuit_satisfied();
}
