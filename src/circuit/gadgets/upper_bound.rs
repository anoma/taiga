use crate::circuit::circuit_parameters::CircuitParameters;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use plonk_core::prelude::StandardComposer;

pub fn upper_bound_gadget<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    CP: CircuitParameters<CurveScalarField = F, InnerCurve = P>,
>(
    composer: &mut StandardComposer<F, P>,
    private_inputs: &[F],
    _public_inputs: &[F],
) {
    // parse the private inputs
    let note_value = private_inputs[0];
    let bound_uint: BigUint = private_inputs[1].into();
    assert!(bound_uint < BigUint::from(u64::MAX));
    let bound = bound_uint.to_usize().unwrap();

    // todo prove the ownership of the note somewhere?
    // upper bound check
    let value_variable = composer.add_input(note_value);
    composer.range_gate(value_variable, bound);
}

#[test]
fn test_upper_bound_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::note::Note;
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;

    // white list addresses
    let mut rng = rand::thread_rng();
    let white_list = (0..4).map(|_| F::rand(&mut rng)).collect::<Vec<F>>();

    // a note owned by one of the white list user
    let note = Note::<CP>::new(
        white_list[1],
        F::rand(&mut rng),
        12,
        <CP as CircuitParameters>::CurveScalarField::rand(&mut rng),
        <CP as CircuitParameters>::CurveScalarField::rand(&mut rng),
        &mut rng,
    );

    let mut composer = StandardComposer::<F, <CP as CircuitParameters>::InnerCurve>::new();
    upper_bound_gadget::<F, P, CP>(&mut composer, &[F::from(note.value), F::from(14)], &[]);
    composer.check_circuit_satisfied();
}
