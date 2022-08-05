use plonk_core::prelude::{Circuit, Error, StandardComposer};

use crate::circuit::circuit_parameters::CircuitParameters;

use crate::circuit::validity_predicate::ValidityPredicate;
use crate::circuit::validity_predicate::NUM_NOTE;
use crate::note::Note;

pub struct TrivialValidityPredicate<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}

impl<CP: CircuitParameters> ValidityPredicate<CP> for TrivialValidityPredicate<CP> {
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.output_notes
    }
}

impl<CP: CircuitParameters> Circuit<CP::CurveScalarField, CP::InnerCurve>
    for TrivialValidityPredicate<CP>
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

impl<CP: CircuitParameters> TrivialValidityPredicate<CP> {
    pub fn new(input_notes: [Note<CP>; NUM_NOTE], output_notes: [Note<CP>; NUM_NOTE]) -> Self {
        Self {
            input_notes,
            output_notes,
        }
    }
}

#[ignore]
#[test]
fn test_vp_creation() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::validity_predicate::NUM_NOTE;
    use crate::note::Note;
    use ark_std::test_rng;
    use plonk_core::prelude::{verify_proof, VerifierData};

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;
    type P = <CP as CircuitParameters>::InnerCurve;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    // creation of the VP
    let mut vp = TrivialValidityPredicate::<CP>::new(input_notes, output_notes);

    // setup of the proof system
    let vp_setup = CP::get_pc_setup_params(vp.padded_circuit_size());

    // proving and verifying keys
    let (pk, vk) = vp.compile::<PC>(vp_setup).unwrap();

    // proof
    let (proof, public_inputs) = vp.gen_proof::<PC>(vp_setup, pk, b"Test").unwrap();

    // verification
    let verifier_data = VerifierData::new(vk, public_inputs);
    verify_proof::<Fr, P, PC>(
        vp_setup,
        verifier_data.key,
        &proof,
        &verifier_data.pi,
        b"Test",
    )
    .unwrap();
}
