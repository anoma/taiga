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

#[test]
fn test_field_addition_vp_example() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type Fq = <CP as CircuitParameters>::CurveBaseField;
    type OP = <CP as CircuitParameters>::Curve;
    type Opc = <CP as CircuitParameters>::OuterCurvePC;
    use crate::circuit::blinding_circuit::BlindingCircuit;
    use crate::utils::ws_to_te;
    use crate::vp_description::ValidityPredicateDescription;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::{test_rng, UniformRand};
    use plonk_core::circuit::{verify_proof, VerifierData};
    use plonk_core::proof_system::pi::PublicInputs;

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

    // Generate blinding circuit for vp
    let vp_desc = ValidityPredicateDescription::from_vp(&mut field_addition_vp, &vp_setup).unwrap();
    let vp_desc_compressed = vp_desc.get_compress();
    let mut blinding_circuit = BlindingCircuit::<CP>::new(
        &mut rng,
        vp_desc,
        &vp_setup,
        field_addition_vp.padded_circuit_size(),
    )
    .unwrap();

    // Compile vp(must use compile_with_blinding)
    let (pk_p, vk_blind) = field_addition_vp
        .compile_with_blinding::<PC>(&vp_setup, &blinding_circuit.get_blinding())
        .unwrap();

    // VP Prover
    let (proof, pi) = field_addition_vp
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

    // Generate blinding circuit CRS
    let blinding_circuit_size = blinding_circuit.padded_circuit_size();
    let pp_blind = Opc::setup(blinding_circuit_size, None, &mut rng).unwrap();
    let (pk_p, vk) = blinding_circuit.compile::<Opc>(&pp_blind).unwrap();

    // Blinding Prover
    let (proof, pi) = blinding_circuit
        .gen_proof::<Opc>(&pp_blind, pk_p, b"Test")
        .unwrap();

    // Expecting vk_blind(out of circuit)
    let mut expect_pi = PublicInputs::new(blinding_circuit_size);
    let q_m = ws_to_te(vk_blind.arithmetic.q_m.0);
    expect_pi.insert(388, q_m.x);
    expect_pi.insert(389, q_m.y);
    let q_l = ws_to_te(vk_blind.arithmetic.q_l.0);
    expect_pi.insert(774, q_l.x);
    expect_pi.insert(775, q_l.y);
    let q_r = ws_to_te(vk_blind.arithmetic.q_r.0);
    expect_pi.insert(1160, q_r.x);
    expect_pi.insert(1161, q_r.y);
    let q_o = ws_to_te(vk_blind.arithmetic.q_o.0);
    expect_pi.insert(1546, q_o.x);
    expect_pi.insert(1547, q_o.y);
    let q_4 = ws_to_te(vk_blind.arithmetic.q_4.0);
    expect_pi.insert(1932, q_4.x);
    expect_pi.insert(1933, q_4.y);
    let q_c = ws_to_te(vk_blind.arithmetic.q_c.0);
    expect_pi.insert(2318, q_c.x);
    expect_pi.insert(2319, q_c.y);
    expect_pi.insert(21364, vp_desc_compressed);

    assert_eq!(pi, expect_pi);

    // Blinding Verifier
    let verifier_data = VerifierData::new(vk, pi);
    verify_proof::<Fq, OP, Opc>(
        &pp_blind,
        verifier_data.key,
        &proof,
        &verifier_data.pi,
        b"Test",
    )
    .unwrap();
}
