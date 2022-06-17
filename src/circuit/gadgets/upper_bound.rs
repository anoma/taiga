use super::bad_hash_to_curve::bad_hash_to_curve_gadget;
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::note::Note;
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, TEModelParameters};
use ark_ff::PrimeField;
use plonk_core::prelude::StandardComposer;

pub fn upper_bound_gadget<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    CP: CircuitParameters<CurveScalarField = F, InnerCurve = P>,
>(
    composer: &mut StandardComposer<F, P>,
    private_note: Note<CP>,
    private_bound: u32,
    public_note_commitment: TEGroupAffine<P>,
) {
    // opening of the note_commitment
    let crh_point = bad_hash_to_curve_gadget::<F, P>(
        composer,
        &vec![
            private_note.owner_address,
            private_note.token_address,
            F::from(private_note.value),
            F::from(private_note.data),
        ],
    );
    composer.assert_equal_public_point(crh_point, public_note_commitment);

    // upper bound check
    let value_variable = composer.add_input(F::from(private_note.value));
    composer.range_gate(value_variable, private_bound.try_into().unwrap());
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
    let note_com = note.commitment();

    let mut composer = StandardComposer::<F, <CP as CircuitParameters>::InnerCurve>::new();
    upper_bound_gadget::<F, P, CP>(&mut composer, note, 14, note_com);
    composer.check_circuit_satisfied();
}
