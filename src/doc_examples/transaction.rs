#[ignore]
#[test]
fn test_tx_example() {
    use crate::action::Action;
    use crate::circuit::action_circuit::ActionCircuit;
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::transaction::*;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use crate::action::ActionInfo;
    use crate::doc_examples::validity_predicate::TrivialValidityPredicate;
    use crate::note::Note;
    use ark_std::test_rng;

    let mut rng = test_rng();

    // Construct action infos
    let mut actions: Vec<(Action<CP>, ActionCircuit<CP>)> = (0..NUM_TX_SLICE)
        .map(|_| {
            let action_info = ActionInfo::<CP>::dummy(&mut rng);
            action_info.build(&mut rng).unwrap()
        })
        .collect();

    // Generate action proofs
    let action_slices: Vec<ActionSlice<CP>> = actions
        .iter_mut()
        .map(|action| ActionSlice::<CP>::build(action.0, &mut action.1).unwrap())
        .collect();

    // Collect input notes from actions
    let input_notes_vec: Vec<Note<CP>> = actions
        .iter()
        .map(|action| action.1.spend_note.clone())
        .collect();
    let input_notes: [Note<CP>; NUM_NOTE] = input_notes_vec.try_into().unwrap();

    // Collect output notes from actions
    let output_notes_vec: Vec<Note<CP>> = actions
        .iter()
        .map(|action| action.1.output_note.clone())
        .collect();
    let output_notes: [Note<CP>; NUM_NOTE] = output_notes_vec.try_into().unwrap();

    // Construct VPs and generate VP proofs and blind VP proofs
    let mut spend_slices = vec![];
    let mut output_slices = vec![];
    for _action_index in 0..NUM_TX_SLICE {
        // Construct dummy spend slice
        let mut spend_addr_vp =
            TrivialValidityPredicate::<CP>::new(input_notes.clone(), output_notes.clone());
        let spend_addr_vp_check = VPCheck::build(&mut spend_addr_vp, &mut rng).unwrap();
        let mut spend_app_vp =
            TrivialValidityPredicate::<CP>::new(input_notes.clone(), output_notes.clone());
        let spend_app_vp_check = VPCheck::build(&mut spend_app_vp, &mut rng).unwrap();
        let spend_slice = SpendSlice::new(spend_addr_vp_check, spend_app_vp_check);
        spend_slices.push(spend_slice);

        // Construct dummy output vps
        let mut output_addr_vp =
            TrivialValidityPredicate::<CP>::new(input_notes.clone(), output_notes.clone());
        let output_addr_vp_check = VPCheck::build(&mut output_addr_vp, &mut rng).unwrap();
        let mut output_app_vp =
            TrivialValidityPredicate::<CP>::new(input_notes.clone(), output_notes.clone());
        let output_app_vp_check = VPCheck::build(&mut output_app_vp, &mut rng).unwrap();
        let output_slice = OutputSlice::new(output_addr_vp_check, output_app_vp_check);
        output_slices.push(output_slice);
    }

    // Construct a tx
    let tx = Transaction::<CP>::new(action_slices, spend_slices, output_slices);

    // Verify the tx
    tx.verify().unwrap();
}
