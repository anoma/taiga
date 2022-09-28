#[ignore]
#[test]
fn test_note_creation() {
    use crate::app::App;
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use crate::nullifier::Nullifier;
    use crate::user::NullifierDerivingKey;
    use crate::user::User;
    use crate::vp_description::ValidityPredicateDescription;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use plonk_core::prelude::Circuit;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    let vp_setup = CP::get_pc_setup_params(vp.padded_circuit_size());

    // app and user
    let desc_vp_app = ValidityPredicateDescription::from_vp(&mut vp, vp_setup).unwrap();
    let desc_vp_send = desc_vp_app.clone();
    let desc_vp_recv = desc_vp_send.clone();

    let app = App::<CP>::new(desc_vp_app);
    let alice = User::<CP>::new(
        desc_vp_send,
        desc_vp_recv,
        NullifierDerivingKey::<Fr>::rand(&mut rng),
    );
    // note
    let nf = Nullifier::<CP>::new(Fr::rand(&mut rng));
    let note = Note::<CP>::new(alice, app, 12, nf, Fr::rand(&mut rng), Fr::rand(&mut rng));

    let _note_commitment = note.commitment();
}
