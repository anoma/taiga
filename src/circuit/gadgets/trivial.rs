use crate::circuit::circuit_parameters::CircuitParameters;
use ark_ff::One;
use plonk_core::prelude::StandardComposer;

pub fn trivial_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    _private_inputs: &Vec<CP::CurveScalarField>,
    _public_inputs: &Vec<CP::CurveScalarField>,
) {
    // no input in this trivial gadget...
    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

#[test]
fn test_trivial_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use plonk_core::constraint_system::StandardComposer;

    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();
    trivial_gadget::<CP>(&mut composer, &vec![], &vec![]);
    composer.check_circuit_satisfied();
}
