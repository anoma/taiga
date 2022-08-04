#[test]
fn test_user_creation() {
    use plonk_core::prelude::Circuit;

    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use crate::user::NullifierDerivingKey;
    use crate::user::User;
    use crate::vp_description::ValidityPredicateDescription;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    let vp_setup = PC::setup(vp.padded_circuit_size(), None, &mut rng).unwrap();

    let desc_vp_send = ValidityPredicateDescription::from_vp(&mut vp, &vp_setup).unwrap();
    let desc_vp_recv = desc_vp_send.clone();

    let alice = User::<CP>::new(
        desc_vp_send,
        desc_vp_recv,
        NullifierDerivingKey::<Fr>::rand(&mut rng),
    );
    let _alice_addr = alice.address().unwrap();
}
