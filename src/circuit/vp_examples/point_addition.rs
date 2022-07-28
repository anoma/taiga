use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::point_addition::point_addition_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::note::Note;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
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

    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::test_rng;
    use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let a = TEGroupAffine::<P>::prime_subgroup_generator();
    let b = TEGroupAffine::<P>::prime_subgroup_generator();
    let c = a + b;
    let mut point_addition_vp = PointAdditionValidityPredicate {
        input_notes,
        output_notes,
        a,
        b,
        c,
    };

    // Generate vp CRS
    let vp_setup = PC::setup(point_addition_vp.padded_circuit_size(), None, &mut rng).unwrap();

    // Compile vp(must use compile_with_blinding)
    let (pk_p, vk_blind) = point_addition_vp.compile::<PC>(&vp_setup).unwrap();

    // VP Prover
    let (proof, pi) = point_addition_vp
        .gen_proof::<PC>(&vp_setup, pk_p, b"Test")
        .unwrap();

    // VP verifier
    let verifier_data = VerifierData::new(vk_blind.clone(), pi);
    verify_proof::<Fr, P, PC>(
        &vp_setup,
        verifier_data.key,
        &proof,
        &verifier_data.pi,
        b"Test",
    )
    .unwrap();
}
