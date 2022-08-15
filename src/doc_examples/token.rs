#[ignore]
#[test]
fn test_token_creation() {
    use ark_std::test_rng;
    use plonk_core::prelude::Circuit;

    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use crate::token::Token;
    use crate::vp_description::ValidityPredicateDescription;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    let vp_setup = CP::get_pc_setup_params(vp.padded_circuit_size());
    let desc_vp = ValidityPredicateDescription::from_vp(&mut vp, vp_setup).unwrap();

    let tok = Token::<CP>::new(desc_vp);

    let _tok_addr = tok.address().unwrap();
}
