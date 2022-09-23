use crate::{
    circuit::{
        circuit_parameters::CircuitParameters,
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
use rand::RngCore;

// FieldAdditionValidityPredicateCircuit with a trivial constraint a + b = c.
#[derive(Clone, Debug, Default)]
struct FieldAdditionValidityPredicateCircuit<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
    a: CP::CurveScalarField,
    b: CP::CurveScalarField,
}

#[derive(Clone, Debug)]
struct FieldAdditionValidityPredicateConfig<CP: CircuitParameters> {
    note_conifg: NoteConfig<CP>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    add_config: AddConfig,
}

impl<CP: CircuitParameters> ValidityPredicateConfig<CP>
    for FieldAdditionValidityPredicateConfig<CP>
{
    fn get_note_config(&self) -> NoteConfig<CP> {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> Self {
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

impl<CP: CircuitParameters> FieldAdditionValidityPredicateCircuit<CP> {
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let a = CP::CurveScalarField::random(&mut rng);
        let b = CP::CurveScalarField::random(&mut rng);
        Self {
            input_notes,
            output_notes,
            a,
            b,
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

        instances.push(self.a + self.b);

        instances
    }
}

impl<CP: CircuitParameters> ValidityPredicateCircuit<CP>
    for FieldAdditionValidityPredicateCircuit<CP>
{
    type Config = FieldAdditionValidityPredicateConfig<CP>;

    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.output_notes
    }

    // Add custom constraints
    // Note: the trivial vp doesn't constrain on input_note_variables and output_note_variables
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<CP::CurveScalarField>,
        _input_note_variables: &[SpendNoteVar<CP>],
        _output_note_variables: &[OutputNoteVar<CP>],
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

        let add_chip = AddChip::<CP::CurveScalarField>::construct(config.add_config, ());

        let c = add_chip.add(layouter.namespace(|| "a + b = c"), &a, &b)?;

        // Public c
        layouter.constrain_instance(c.cell(), config.instances, 8)?;

        Ok(())
    }
}

vp_circuit_impl!(FieldAdditionValidityPredicateCircuit, CP);

#[test]
fn test_halo2_addition_vp_circuit() {
    use crate::circuit::circuit_parameters::DLCircuitParameters as CP;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = FieldAdditionValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<CP::CurveScalarField>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
