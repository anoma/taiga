use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::scalar_multiplication::scalar_multiplication_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::note::Note;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};

// ScalarMultiplicationValidityPredicate have a custom constraint with a + b = c,
// in which a, b are private inputs and c is a public input.
pub struct ScalarMultiplicationValidityPredicate<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
    // custom "private" inputs to the VP
    n: CP::CurveScalarField,
    // custom "public" inputs to the VP
    pub c: TEGroupAffine<CP::InnerCurve>,
}

impl<CP> ValidityPredicate<CP> for ScalarMultiplicationValidityPredicate<CP>
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
        let var_n = composer.add_input(self.n);
        let output =
            scalar_multiplication_gadget::<CP::CurveScalarField, CP::InnerCurve>(composer, var_n);
        composer.assert_equal_public_point(output, self.c);
        Ok(())
    }
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for ScalarMultiplicationValidityPredicate<CP>
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
fn test_scalar_multiplication_vp_example() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use ark_ec::group::Group;
    use ark_ec::TEModelParameters;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::test_rng;
    use plonk_core::circuit::{verify_proof, VerifierData};

    // (useless) notes
    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    let (x, y) = P::AFFINE_GENERATOR_COEFFS;
    let fixed_base = TEGroupAffine::<P>::new(x, y);
    // for a generic n, we need to use a InnerCurveScalarField element and then convert it to a Fr element for the circuit
    let n = Fr::from(12);
    let c = fixed_base.double().double().double() + fixed_base.double().double();
    let mut scalar_multiplication_vp = ScalarMultiplicationValidityPredicate {
        input_notes,
        output_notes,
        n,
        c,
    };

    // Generate vp CRS
    let vp_setup = PC::setup(
        scalar_multiplication_vp.padded_circuit_size(),
        None,
        &mut rng,
    )
    .unwrap();

    // Compile vp(must use compile_with_blinding)
    let (pk_p, vk_blind) = scalar_multiplication_vp.compile::<PC>(&vp_setup).unwrap();

    // VP Prover
    let (proof, pi) = scalar_multiplication_vp
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