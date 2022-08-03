pub const NUM_NOTE: usize = 4;
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::integrity::{
    input_note_constraint, output_note_constraint, ValidityPredicateInputNoteVariables,
    ValidityPredicateOutputNoteVariables,
};
use crate::note::Note;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{
    circuit::Circuit,
    constraint_system::StandardComposer,
    error::to_pc_error,
    prelude::Error,
    proof_system::{verifier::Verifier, VerifierKey},
};

pub trait ValidityPredicate<CP: CircuitParameters>:
    Circuit<CP::CurveScalarField, CP::InnerCurve>
{
    // Default implementation, used in gadgets function in Circuit trait.
    fn gadget_vp(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        let (input_note_variables, output_note_variables) = self.basic_constraints(composer)?;
        self.custom_constraints(composer, &input_note_variables, &output_note_variables)
    }

    // Default implementation, constrains the notes integrity and outputs variables of notes.
    fn basic_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<
        (
            Vec<ValidityPredicateInputNoteVariables>,
            Vec<ValidityPredicateOutputNoteVariables>,
        ),
        Error,
    > {
        let input_notes = self.get_input_notes();
        let output_notes = self.get_output_notes();
        let mut input_note_variables = vec![];
        let mut output_note_variables = vec![];
        for i in 0..NUM_NOTE {
            let input_note_var = input_note_constraint(&input_notes[i], composer)?;
            let output_note_var =
                output_note_constraint(&output_notes[i], &input_note_var.nf, composer)?;
            input_note_variables.push(input_note_var);
            output_note_variables.push(output_note_var);
        }
        Ok((input_note_variables, output_note_variables))
    }

    fn get_desc_vp(
        &mut self,
        vp_setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
    ) -> Result<VerifierKey<CP::CurveScalarField, CP::CurvePC>, Error> {
        let (ck, _) = CP::CurvePC::trim(vp_setup, self.padded_circuit_size(), 0, None)
            .map_err(to_pc_error::<CP::CurveScalarField, CP::CurvePC>)?;
        let mut verifier = Verifier::new(b"CircuitCompilation");
        self.gadget(verifier.mut_cs())?;
        verifier
            .cs
            .public_inputs
            .update_size(verifier.circuit_bound());
        verifier.preprocess(&ck)?;
        Ok(verifier
            .verifier_key
            .expect("Unexpected error. Missing VerifierKey in compilation"))
    }

    // VP designer should implement the following functions.
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE];
    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE];
    fn custom_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        input_note_variables: &[ValidityPredicateInputNoteVariables],
        output_note_variables: &[ValidityPredicateOutputNoteVariables],
    ) -> Result<(), Error>;
}
