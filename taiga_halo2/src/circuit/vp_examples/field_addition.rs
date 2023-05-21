use crate::{
    circuit::{
        gadgets::{
            add::{AddChip, AddConfig, AddInstructions},
            assign_free_advice,
        },
        note_circuit::NoteConfig,
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP, VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX},
    note::Note,
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

// FieldAdditionValidityPredicateCircuit with a trivial constraint a + b = c.
#[derive(Clone, Debug, Default)]
struct FieldAdditionValidityPredicateCircuit {
    owned_note_pub_id: pallas::Base,
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
        let owned_note_pub_id = pallas::Base::zero();
        Self {
            owned_note_pub_id,
            input_notes,
            output_notes,
            a,
            b,
        }
    }
}

impl ValidityPredicateInfo for FieldAdditionValidityPredicateCircuit {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();

        instances.push(self.a + self.b);

        instances
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

impl ValidityPredicateCircuit for FieldAdditionValidityPredicateCircuit {
    type VPConfig = FieldAdditionValidityPredicateConfig;
    // Add custom constraints
    // Note: the trivial vp doesn't constrain on input_note_variables and output_note_variables
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        _basic_variables: BasicValidityPredicateVariables,
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
        layouter.constrain_instance(
            c.cell(),
            config.instances,
            VP_CIRCUIT_CUSTOM_INSTANCE_BEGIN_IDX,
        )?;

        Ok(())
    }
}

vp_circuit_impl!(FieldAdditionValidityPredicateCircuit);

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
