use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::point_addition::point_addition_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::note::Note;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use plonk_core::proof_system::{Blinding, Prover, Verifier};
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};

// PointAdditionValidityPredicate have a custom constraint with a + b = c,
// in which a, b are private inputs and c is a public input.
pub struct PointAdditionValidityPredicate<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
    // custom "private" inputs to the VP
    a: TEGroupAffine<CP::InnerCurve>,
    b: TEGroupAffine<CP::InnerCurve>,
    // custom "public" inputs to the VP
    pub c: TEGroupAffine<CP::InnerCurve>,
}

impl<CP> ValidityPredicate<CP> for PointAdditionValidityPredicate<CP>
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
        let var_a = composer.add_affine(self.a);
        let var_b = composer.add_affine(self.b);
        let var_a_plus_b =
            point_addition_gadget::<CP::CurveScalarField, CP::InnerCurve>(composer, var_a, var_b);
        let var_c = composer.add_affine(self.c);
        composer.assert_equal_point(var_c, var_a_plus_b);
        Ok(())
    }
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for PointAdditionValidityPredicate<CP>
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
fn test_point_addition_vp_example() {
    use ark_ec::AffineCurve;
    use rand::rngs::OsRng;

    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    type OPC = <CP as CircuitParameters>::OuterCurvePC;
    use ark_poly_commit::PolynomialCommitment;

    let u_params = OPC::setup(2 * 30, None, &mut OsRng).unwrap();

    // Create a prover struct
    let mut prover: Prover<Fq, OP, OPC> = Prover::new(b"demo");

    let composer = prover.mut_cs();

    // points for my test
    let a = TEGroupAffine::<OP>::prime_subgroup_generator();
    let var_a = composer.add_affine(a);
    let b = TEGroupAffine::<OP>::prime_subgroup_generator();
    let var_b = composer.add_affine(b);
    let c = a + b;

    // Add gadgets
    let output_point = point_addition_gadget::<Fq, OP>(composer, var_a, var_b);
    composer.assert_equal_public_point(output_point, c);

    // Commit Key
    let (ck, vk) = OPC::trim(&u_params, 2 * 20, 0, None).unwrap();

    // Preprocess circuit
    prover.preprocess(&ck).unwrap();

    let public_inputs = prover.cs.get_pi().clone();

    let proof = prover.prove(&ck).unwrap();

}
