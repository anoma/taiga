use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::field_addition::field_addition_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::note::Note;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};

// FieldAdditionValidityPredicate have a custom constraint with a + b = c,
// in which a, b are private inputs and c is a public input.
pub struct FieldAdditionValidityPredicate<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    pub input_notes: [Note<CP>; NUM_NOTE],
    pub output_notes: [Note<CP>; NUM_NOTE],
    // custom "private" inputs to the VP
    pub a: CP::CurveScalarField,
    pub b: CP::CurveScalarField,
    // custom "public" inputs to the VP
    pub c: CP::CurveScalarField,
}

impl<CP> ValidityPredicate<CP> for FieldAdditionValidityPredicate<CP>
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
        _input_note_variables: &[ValidityPredicateInputNoteVariables],
        _output_note_variables: &[ValidityPredicateOuputNoteVariables],
    ) -> Result<(), Error> {
        let var_a = composer.add_input(self.a);
        let var_b = composer.add_input(self.b);
        let var_a_plus_b = field_addition_gadget::<CP>(composer, var_a, var_b);
        let var_c = composer.add_input(self.c);
        composer.assert_equal(var_c, var_a_plus_b);
        Ok(())
    }
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for FieldAdditionValidityPredicate<CP>
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

#[test]
fn test_field_addition_vp_example() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::{test_rng, UniformRand};
    use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let c = a + b;
    let mut field_addition_vp = FieldAdditionValidityPredicate {
        input_notes,
        output_notes,
        a,
        b,
        c,
    };

    // Generate CRS
    let pp = PC::setup(field_addition_vp.padded_circuit_size(), None, &mut rng).unwrap();

    // Compile the circuit
    let (pk_p, vk) = field_addition_vp.compile::<PC>(&pp).unwrap();

    // Prover
    let (proof, pi) = field_addition_vp
        .gen_proof::<PC>(&pp, pk_p, b"Test")
        .unwrap();

    // Verifier
    let verifier_data = VerifierData::new(vk, pi);
    verify_proof::<Fr, P, PC>(&pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
