use crate::{
    circuit::{
        gadgets::{assign_free_advice, AddChip, AddConfig, AddInstructions},
        integrity::{OutputNoteVar, SpendNoteVar},
        note_circuit::NoteConfig,
        vp_circuit::{ValidityPredicateCircuit, ValidityPredicateConfig},
    },
    constant::NUM_NOTE,
    note::Note,
};
use ff::Field;
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;
use rand::RngCore;

// FieldAdditionValidityPredicateCircuit with a trivial constraint a + b = c.
#[derive(Clone, Debug, Default)]
struct FieldAdditionValidityPredicateCircuit {
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    a: pallas::Base,
    b: pallas::Base,
}

#[derive(Clone, Debug)]
struct FieldAdditionValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    add_config: AddConfig,
}

impl ValidityPredicateConfig for FieldAdditionValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let instances = note_conifg.instances;

        // configure custom config here
        let add_config = note_conifg.add_config.clone();

        Self {
            note_conifg,
            advices,
            instances,
            add_config,
        }
    }
}

impl FieldAdditionValidityPredicateCircuit {
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let a = pallas::Base::random(&mut rng);
        let b = pallas::Base::random(&mut rng);
        Self {
            input_notes,
            output_notes,
            a,
            b,
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

        instances.push(self.a + self.b);

        instances
    }
}

impl ValidityPredicateCircuit for FieldAdditionValidityPredicateCircuit {
    type Config = FieldAdditionValidityPredicateConfig;

    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    // Add custom constraints
    // Note: the trivial vp doesn't constrain on input_note_variables and output_note_variables
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        _input_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), Error> {
        let a = assign_free_advice(
            layouter.namespace(|| "witness a"),
            config.advices[0],
            Value::known(self.a),
        )?;

        let b = assign_free_advice(
            layouter.namespace(|| "witness b"),
            config.advices[1],
            Value::known(self.b),
        )?;

        let add_chip = AddChip::<pallas::Base>::construct(config.add_config, ());

        let c = add_chip.add(layouter.namespace(|| "a + b = c"), &a, &b)?;

        // Public c
        layouter.constrain_instance(c.cell(), config.instances, 8)?;

        Ok(())
    }
}

// TODO: The `Circuit` impl for all vp circuits is the same, try to make it a Macros
impl Circuit<pallas::Base> for FieldAdditionValidityPredicateCircuit {
    type Config = FieldAdditionValidityPredicateConfig;
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
fn test_halo2_addition_vp_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = FieldAdditionValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
