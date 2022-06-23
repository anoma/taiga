use crate::circuit::circuit_parameters::{PairingCircuitParameters, CircuitParameters};
use plonk_core::prelude::StandardComposer;
use plonk_core::constraint_system::Variable;
type CircuitPoint = plonk_core::constraint_system::ecc::Point<<PairingCircuitParameters as CircuitParameters>::InnerCurve>;
use ark_poly_commit::sonic_pc::CommitterKey;

type InnerCurve = ark_bls12_377::Bls12_377;

pub fn blinding_gadget(
    composer: &mut StandardComposer<<PairingCircuitParameters as CircuitParameters>::CurveScalarField, <PairingCircuitParameters as CircuitParameters>::InnerCurve>,
    blinding_scalar: Variable, 
    polynomial: CircuitPoint,
    ck: &CommitterKey<InnerCurve>,
) -> CircuitPoint {

    let p = composer.fixed_base_scalar_mul(blinding_scalar, ck.powers_of_g[1]); //todo: is this the right power?

    composer.point_addition_gate(p, polynomial) // [blinding_scalar] * ck_1 + polynomial
}

#[test]
fn test_field_addition_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
    use plonk_core::constraint_system::StandardComposer;

    let blinding_scalar = <PairingCircuitParameters as CircuitParameters>::CurveScalarField::from(1u64);
    let mut composer = StandardComposer::<
        <PairingCircuitParameters as CircuitParameters> ::CurveScalarField,
        <PairingCircuitParameters as CircuitParameters>::InnerCurve,
    >::new();
    // TODO
    //blinding_gadget(&mut composer, &[a, b], &[c]); 
    composer.check_circuit_satisfied();
}
