use crate::{
    circuit::{
        note_circuit::NoteConfig,
        vp_circuit::{ValidityPredicateCircuit, ValidityPredicateConfig},
    },
    constant::NUM_NOTE,
    note::Note,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas;
use rand::RngCore;

use super::circuit_parameters::CircuitParameters;

mod field_addition;

// DummyValidityPredicateCircuit with empty custom constraints.
#[derive(Clone, Debug, Default)]
pub struct DummyValidityPredicateCircuit<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}

#[derive(Clone, Debug)]
pub struct DummyValidityPredicateConfig {
    note_conifg: NoteConfig,
}

impl<CP: CircuitParameters> ValidityPredicateConfig<CP> for DummyValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> Self {
        let note_conifg = Self::configure_note(meta);
        Self { note_conifg }
    }
}

impl<CP: CircuitParameters> DummyValidityPredicateCircuit<CP> {
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        Self {
            input_notes,
            output_notes,
        }
    }

    pub fn get_instances(&self) -> Vec<CP::CurveScalarField> {
        let mut instances = vec![];
        self.input_notes
            .iter()
            .zip(self.output_notes.iter())
            .for_each(|(input_note, output_note)| {
                let nf = input_note.get_nf().inner();
                instances.push(nf);
                let cm = output_note.commitment();
                instances.push(cm.get_x());
            });

        instances
    }
}

impl<CP> ValidityPredicateCircuit<CP> for DummyValidityPredicateCircuit<CP> {
    type Config = DummyValidityPredicateConfig;

    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.output_notes
    }
}

vp_circuit_impl!(DummyValidityPredicateCircuit<_>,CP);

#[test]
fn test_halo2_dummy_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = DummyValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<CP::CurveScalarField>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
