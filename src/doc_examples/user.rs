use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::integrity::{
    token_integrity_circuit, ValidityPredicateInputNoteVariables,
    ValidityPredicateOutputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::note::Note;
use crate::token::Token;
use ark_std;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};

pub struct SendVP<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}

impl<CP: CircuitParameters> SendVP<CP> {
    pub fn new(input_notes: [Note<CP>; NUM_NOTE], output_notes: [Note<CP>; NUM_NOTE]) -> Self {
        SendVP {
            input_notes,
            output_notes,
        }
    }
}

impl<CP> ValidityPredicate<CP> for SendVP<CP>
where
    CP: CircuitParameters,
{
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.output_notes
    }

    fn custom_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        input_note_variables: &[ValidityPredicateInputNoteVariables],
        _output_note_variables: &[ValidityPredicateOutputNoteVariables],
    ) -> Result<(), Error> {
        // * Alice does not want to send more than 3 XAN at a time.
        let mut rng = ark_std::test_rng();
        let xan_token =
            Token::<crate::circuit::circuit_parameters::PairingCircuitParameters>::dummy(&mut rng);

        let (xan_address_var, _) =
            token_integrity_circuit::<CP>(composer, &xan_token.token_vp.to_bits())?;

        // Check that the token of all the notes of token XAN are less than 3 XAN
        for note_var in input_note_variables {
            composer.assert_equal(note_var.token_addr, xan_address_var);
            // TODO: Check that the note value is less than 3
        }

        Ok(())
    }
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for SendVP<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        self.gadget_vp(composer)
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 17
    }
}

pub struct ReceiveVP<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}

impl<CP: CircuitParameters> ReceiveVP<CP> {
    pub fn new(input_notes: [Note<CP>; NUM_NOTE], output_notes: [Note<CP>; NUM_NOTE]) -> Self {
        ReceiveVP {
            input_notes,
            output_notes,
        }
    }
}

impl<CP> ValidityPredicate<CP> for ReceiveVP<CP>
where
    CP: CircuitParameters,
{
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.output_notes
    }

    fn custom_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        input_note_variables: &[ValidityPredicateInputNoteVariables],
        _output_note_variables: &[ValidityPredicateOutputNoteVariables],
    ) -> Result<(), Error> {
        // * Alice does not want to send more than 3 XAN at a time.
        let mut rng = ark_std::test_rng();
        let xan_token =
            Token::<crate::circuit::circuit_parameters::PairingCircuitParameters>::dummy(&mut rng);

        let (xan_address_var, _) =
            token_integrity_circuit::<CP>(composer, &xan_token.token_vp.to_bits())?;

        // Check that the token of all the notes of token XAN are less than 3 XAN
        for note_var in input_note_variables {
            composer.assert_equal(note_var.token_addr, xan_address_var);
            // TODO: Check that the note value is less than 3
        }

        Ok(())
    }
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for ReceiveVP<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        self.gadget_vp(composer)
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 17
    }
}

#[ignore]
#[test]
fn test_user_creation() {
    use plonk_core::prelude::Circuit;

    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::note::Note;
    use crate::user::NullifierDerivingKey;
    use crate::user::User;
    use crate::vp_description::ValidityPredicateDescription;
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let send_input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let send_output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let mut send_vp = SendVP::<CP>::new(send_input_notes, send_output_notes);

    let receive_input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let receive_output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let mut receive_vp = ReceiveVP::<CP>::new(receive_input_notes, receive_output_notes);

    let vp_setup = CP::get_pc_setup_params(send_vp.padded_circuit_size());

    let desc_vp_send = ValidityPredicateDescription::from_vp(&mut send_vp, vp_setup).unwrap();
    let desc_vp_recv = ValidityPredicateDescription::from_vp(&mut receive_vp, vp_setup).unwrap();

    let alice = User::<CP>::new(
        desc_vp_send,
        desc_vp_recv,
        NullifierDerivingKey::<Fr>::rand(&mut rng),
    );
    let _alice_addr = alice.address().unwrap();
}
