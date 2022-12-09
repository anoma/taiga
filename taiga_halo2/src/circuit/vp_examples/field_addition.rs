use crate::{
    circuit::{
        gadgets::{assign_free_advice, AddChip, AddConfig, AddInstructions},
        integrity::{OutputNoteVar, SpendNoteVar},
        note_circuit::NoteConfig,
        vp_circuit::{ValidityPredicateCircuit, ValidityPredicateConfig, ValidityPredicateInfo},
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
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
    spend_notes: [Note; NUM_NOTE],
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
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let a = pallas::Base::random(&mut rng);
        let b = pallas::Base::random(&mut rng);
        Self {
            spend_notes,
            output_notes,
            a,
            b,
        }
    }
}

impl ValidityPredicateInfo for FieldAdditionValidityPredicateCircuit {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();

        instances.push(self.a + self.b);

        instances
    }

    fn generate_proof(&self) -> Vec<u8> {
        use halo2_proofs::{
            plonk::{create_proof, keygen_pk, keygen_vk},
            poly::commitment::Params,
            transcript:: Blake2bWrite,
        };
        use rand::rngs::OsRng;
        use pasta_curves::vesta;

        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        let pk = keygen_pk(params, vk, self).expect("keygen_pk should not fail");
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        create_proof(
            params,
            &pk,
            &[self.clone()],
            &[&[&self.get_instances()]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    }
}

impl ValidityPredicateCircuit for FieldAdditionValidityPredicateCircuit {
    type VPConfig = FieldAdditionValidityPredicateConfig;
    // Add custom constraints
    // Note: the trivial vp doesn't constrain on spend_note_variables and output_note_variables
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        _spend_note_variables: &[SpendNoteVar],
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
        layouter.constrain_instance(c.cell(), config.instances, 2 * NUM_NOTE)?;

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
