use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::field_addition::field_addition_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOutputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::note::Note;
use ark_ff::UniformRand;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};
use rand::RngCore;

// FieldAdditionValidityPredicate have a custom constraint with a + b = c,
// in which a, b are private inputs and c is a public input.
pub struct FieldAdditionValidityPredicate<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
    // custom "private" inputs to the VP
    a: CP::CurveScalarField,
    b: CP::CurveScalarField,
    // custom "public" inputs to the VP
    pub c: CP::CurveScalarField,
}

impl<CP: CircuitParameters> FieldAdditionValidityPredicate<CP> {
    pub fn new(
        input_notes: [Note<CP>; NUM_NOTE],
        output_notes: [Note<CP>; NUM_NOTE],
        rng: &mut impl RngCore,
    ) -> Self {
        let a = CP::CurveScalarField::rand(rng);
        let b = CP::CurveScalarField::rand(rng);
        let c = a + b;
        Self {
            input_notes,
            output_notes,
            a,
            b,
            c,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(rng));
        let a = CP::CurveScalarField::rand(rng);
        let b = CP::CurveScalarField::rand(rng);
        let c = a + b;
        Self {
            input_notes,
            output_notes,
            a,
            b,
            c,
        }
    }
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
        _output_note_variables: &[ValidityPredicateOutputNoteVariables],
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

#[ignore]
#[test]
fn test_field_addition_vp_example() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use ark_std::test_rng;
    use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let mut field_addition_vp = FieldAdditionValidityPredicate::<CP>::dummy(&mut rng);

    // Generate vp CRS
    let vp_setup = CP::get_pc_setup_params(field_addition_vp.padded_circuit_size());

    // Compile vp(must use compile_with_blinding)
    let (pk, vk_blind) = field_addition_vp.compile::<PC>(vp_setup).unwrap();

    // VP Prover
    let (proof, public_input) = field_addition_vp
        .gen_proof::<PC>(vp_setup, pk, b"Test")
        .unwrap();

    // VP verifier
    let verifier_data = VerifierData::new(vk_blind, public_input);
    verify_proof::<Fr, P, PC>(
        vp_setup,
        verifier_data.key,
        &proof,
        &verifier_data.pi,
        b"Test",
    )
    .unwrap();
}
