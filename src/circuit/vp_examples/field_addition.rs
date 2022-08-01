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
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
    // custom "private" inputs to the VP
    a: CP::CurveScalarField,
    b: CP::CurveScalarField,
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

    // Generate vp CRS
    let vp_setup = PC::setup(field_addition_vp.padded_circuit_size(), None, &mut rng).unwrap();

    // Compile vp(must use compile_with_blinding)
    let (pk_p, vk_blind) = field_addition_vp.compile::<PC>(&vp_setup).unwrap();

    // VP Prover
    let (proof, pi) = field_addition_vp
        .gen_proof::<PC>(&vp_setup, pk_p, b"Test")
        .unwrap();

    // VP verifier
    let verifier_data = VerifierData::new(vk_blind, pi);
    verify_proof::<Fr, P, PC>(
        &vp_setup,
        verifier_data.key,
        &proof,
        &verifier_data.pi,
        b"Test",
    )
    .unwrap();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AdditionCircuit<CP: CircuitParameters> {
    a: CP::CurveScalarField,
    b: CP::CurveScalarField,
    pub c: CP::CurveScalarField,
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for AdditionCircuit<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        let var_a = composer.add_input(self.a);
        let var_b = composer.add_input(self.b);
        let var_c = composer.add_input(self.c);
        // add a gate for the addition
        let var_a_plus_b = field_addition_gadget::<CP>(composer, var_a, var_b);
        // // check that a + b == c
        composer.assert_equal(var_c, var_a_plus_b);
        composer.check_circuit_satisfied();
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 5
    }
}

#[test]
fn test_circuit_example() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::{test_rng, UniformRand};
    use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let a = F::rand(&mut rng);
    let b = F::rand(&mut rng);
    let c = a + b;

    // Circuit
    let mut circuit = AdditionCircuit::<CP> { a, b, c };

    // Setup
    let setup = PC::setup(circuit.padded_circuit_size(), None, &mut rng).unwrap();

    // Verifier key
    let (pk, vk) = circuit.compile::<PC>(&setup).unwrap();

    // VP Prover
    let (pi, public_inputs) = circuit.gen_proof::<PC>(&setup, pk, b"Test").unwrap();

    // VP verifier
    let verifier_data = VerifierData::new(vk, public_inputs);
    verify_proof::<F, P, PC>(&setup, verifier_data.key, &pi, &verifier_data.pi, b"Test").unwrap();
}
