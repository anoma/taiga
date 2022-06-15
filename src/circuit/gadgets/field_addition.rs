use crate::circuit::circuit_parameters::CircuitParameters;
use ark_ff::{One, Zero};
use plonk_core::prelude::StandardComposer;

pub fn field_addition_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    private_inputs: &Vec<CP::CurveScalarField>,
    public_inputs: &Vec<CP::CurveScalarField>,
) {
    // simple circuit that checks that a + b == c
    let (a, b) = if private_inputs.len() == 0 {
        (CP::CurveScalarField::zero(), CP::CurveScalarField::zero())
    } else {
        (private_inputs[0], private_inputs[1])
    };
    let c = public_inputs[0];
    let one = <CP as CircuitParameters>::CurveScalarField::one();
    let var_a = composer.add_input(a);
    let var_b = composer.add_input(b);
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
    use crate::circuit::circuit_parameters::{
        CircuitParameters, PairingCircuitParameters as CP,
    };
    use plonk_core::constraint_system::StandardComposer;

    let a = <CP as CircuitParameters>::CurveScalarField::from(2u64);
    let b = <CP as CircuitParameters>::CurveScalarField::from(1u64);
    let c = <CP as CircuitParameters>::CurveScalarField::from(3u64);
    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();
    field_addition_gadget::<CP>(&mut composer, &vec![a, b], &vec![c]);
    composer.check_circuit_satisfied();
}

