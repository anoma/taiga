use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::prelude::{Circuit, StandardComposer, Error};

use crate::circuit::circuit_parameters::CircuitParameters;

pub struct AdditionCircuit<F:PrimeField> {
    a: F,
    b: F,
    pub c: F,
}

impl<F, P> Circuit<F, P> for AdditionCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField=F>,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<F, P>,
    ) -> Result<(), Error> {
        let var_a = composer.add_input(self.a);
        let var_b = composer.add_input(self.b);
        // add a gate for the addition
        let var_zero = composer.zero_var();
        // Make first constraint a + b = c (as public input)
        composer.arithmetic_gate(|gate| {
            gate.witness(var_a, var_b, Some(var_zero))
                .add(F::one(), F::one())
                .pi(-self.c)
        });
        composer.check_circuit_satisfied();
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 3
    }
}

#[test]
fn test_circuit_example() {
    use crate::circuit::circuit_parameters::CircuitParameters;
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
    let mut circuit = AdditionCircuit::<F> { a, b, c };
    // Setup
    let setup = PC::setup(Circuit::<F, P>::padded_circuit_size(&circuit), None, &mut rng).unwrap();
    // Prover and verifier key
    let (pk, vk) = Circuit::<F, P>::compile::<PC>(&mut circuit, &setup).unwrap();
    // Proof computation
    let (pi, public_inputs) = Circuit::<F, P>::gen_proof::<PC>(&mut circuit, &setup, pk, b"Test").unwrap();
    // Proof verification
    let verifier_data = VerifierData::new(vk, public_inputs);
    verify_proof::<F, P, PC>(&setup, verifier_data.key, &pi, &verifier_data.pi, b"Test").unwrap();
}




/////////////////////////////////////////////////////////////////

use crate::circuit::validity_predicate::NUM_NOTE;
use crate::note::Note;
use crate::vp_description::ValidityPredicateDescription;
use crate::circuit::validity_predicate::ValidityPredicate;
use crate::circuit::integrity::ValidityPredicateInputNoteVariables;
use crate::circuit::integrity::ValidityPredicateOuputNoteVariables;

pub struct TrivialValidityPredicate<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}

impl<CP> ValidityPredicate<CP> for TrivialValidityPredicate<CP>
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
        _composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        _input_note_variables: &[ValidityPredicateInputNoteVariables],
        _output_note_variables: &[ValidityPredicateOuputNoteVariables],
    ) -> Result<(), Error> {
        Ok(())
    }
}
impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for TrivialValidityPredicate<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        _composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        // nothing
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 3
    }
}

#[test]
fn test_token_creation() {
    use ark_std::test_rng;
    use crate::token::Token;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::note::Note; 
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;
    use ark_poly_commit::PolynomialCommitment;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
   
    let mut vp = TrivialValidityPredicate::<CP> {
        input_notes,
        output_notes,
    };

    // Generate vp CRS
    let vp_setup = PC::setup(vp.padded_circuit_size(), None, &mut rng).unwrap();
    let desc_vp = ValidityPredicateDescription::from_vp(&mut vp, &vp_setup).unwrap();

    let tok = Token::<CP>::new(desc_vp);

    // Compile vp(must use compile_with_blinding)
    let (pk, vk) = vp.compile::<PC>(&vp_setup).unwrap();

}