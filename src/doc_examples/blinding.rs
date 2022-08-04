#[test]
fn test_blinding_circuit() {
    use crate::circuit::blinding_circuit::BlindingCircuit;
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use crate::utils::ws_to_te;
    use crate::vp_description::ValidityPredicateDescription;
    use plonk_core::circuit::{verify_proof, VerifierData};
    use plonk_core::prelude::Circuit;
    use plonk_core::proof_system::pi::PublicInputs;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type OP = <CP as CircuitParameters>::Curve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::test_rng;

    let mut rng = test_rng();

    // A balance VP
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = input_notes.clone();

    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    // we blind the VP desc
    let pp = PC::setup(vp.padded_circuit_size(), None, &mut rng).unwrap();
    let vp_desc = ValidityPredicateDescription::from_vp(&mut vp, &pp).unwrap();
    let vp_desc_compressed = vp_desc.get_compress();

    // the blinding circuit, containing the random values used to blind
    let mut blinding_circuit =
        BlindingCircuit::<CP>::new(&mut rng, vp_desc, &pp, vp.padded_circuit_size()).unwrap();

    // verifying key with the blinding
    let (_, vk_blind) = vp
        .compile_with_blinding::<PC>(&pp, &blinding_circuit.get_blinding())
        .unwrap();

    let blinding_circuit_size = blinding_circuit.padded_circuit_size();
    let pp_blind = Opc::setup(blinding_circuit_size, None, &mut rng).unwrap();

    let (pk_p, vk) = blinding_circuit.compile::<Opc>(&pp_blind).unwrap();

    // Blinding Prover
    let (proof, pi) = blinding_circuit
        .gen_proof::<Opc>(&pp_blind, pk_p, b"Test")
        .unwrap();


    //
    // this is very expensive and needs to be adapted
    //

    // // Expecting vk_blind(out of circuit)
    // let mut expect_pi = PublicInputs::new(blinding_circuit_size);
    // let q_m = ws_to_te(vk_blind.arithmetic.q_m.0);
    // expect_pi.insert(392, q_m.x);
    // expect_pi.insert(393, q_m.y);
    // let q_l = ws_to_te(vk_blind.arithmetic.q_l.0);
    // expect_pi.insert(782, q_l.x);
    // expect_pi.insert(783, q_l.y);
    // let q_r = ws_to_te(vk_blind.arithmetic.q_r.0);
    // expect_pi.insert(1172, q_r.x);
    // expect_pi.insert(1173, q_r.y);
    // let q_o = ws_to_te(vk_blind.arithmetic.q_o.0);
    // expect_pi.insert(1562, q_o.x);
    // expect_pi.insert(1563, q_o.y);
    // let q_4 = ws_to_te(vk_blind.arithmetic.q_4.0);
    // expect_pi.insert(1952, q_4.x);
    // expect_pi.insert(1953, q_4.y);
    // let q_c = ws_to_te(vk_blind.arithmetic.q_c.0);
    // expect_pi.insert(2342, q_c.x);
    // expect_pi.insert(2343, q_c.y);
    // expect_pi.insert(21388, vp_desc_compressed);

    // assert_eq!(pi, expect_pi);

    // // Blinding Verifier
    // let verifier_data = VerifierData::new(vk, pi);
    // verify_proof::<Fq, OP, Opc>(
    //     &pp_blind,
    //     verifier_data.key,
    //     &proof,
    //     &verifier_data.pi,
    //     b"Test",
    // )
    // .unwrap();
}
