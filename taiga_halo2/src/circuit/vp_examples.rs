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

// DummyValidityPredicateCircuit with empty custom constraints.
#[derive(Clone, Debug, Default)]
struct DummyValidityPredicateCircuit {
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
}

#[derive(Clone, Debug)]
struct DummyValidityPredicateConfig {
    note_conifg: NoteConfig,
}

impl ValidityPredicateConfig for DummyValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);
        Self { note_conifg }
    }
}

impl DummyValidityPredicateCircuit {
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        Self {
            input_notes,
            output_notes,
        }
    }

    pub fn get_instances(&self) -> Vec<pallas::Base> {
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

impl ValidityPredicateCircuit for DummyValidityPredicateCircuit {
    type Config = DummyValidityPredicateConfig;

    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }
}

// TODO: The `Circuit` impl for all vp circuits is the same, try to make it a Macros
impl Circuit<pallas::Base> for DummyValidityPredicateCircuit {
    type Config = DummyValidityPredicateConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        Self::Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let (input_note_variables, output_note_variables) =
            self.basic_constraints(config.clone(), layouter.namespace(|| "basic constraints"))?;
        self.custom_constraints(
            config,
            layouter.namespace(|| "custom constraints"),
            &input_note_variables,
            &output_note_variables,
        )?;
        Ok(())
    }
}

#[test]
fn test_halo2_dummy_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = DummyValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
