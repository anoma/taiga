use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;
use taiga_halo2::{
    circuit::{
        gadgets::{assign_free_advice, GetTargetNoteVariableConfig},
        integrity::{OutputNoteVar, SpendNoteVar},
        note_circuit::NoteConfig,
        vp_circuit::{
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
    proof::Proof,
    vp_circuit_impl,
    vp_vk::ValidityPredicateVerifyingKey,
};

// IntentAppValidityPredicateCircuit with a trivial constraint a + b = c.
#[derive(Clone, Debug, Default)]
struct IntentAppValidityPredicateCircuit {
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // The note that vp owned is set at spend_notes[0] or output_notes[0] by default. Make it mandatory later.
    // is_spend_note helps locate the target note in spend_notes and output_notes.
    is_spend_note: pallas::Base,
    // dealer_intent_vp_vk: ValidityPredicateVerifyingKey,
}

#[derive(Clone, Debug)]
struct IntentAppValidityPredicateConfig {
    note_conifg: NoteConfig,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    get_target_variable_config: GetTargetNoteVariableConfig,
}

impl ValidityPredicateConfig for IntentAppValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let instances = note_conifg.instances;
        let get_target_variable_config = GetTargetNoteVariableConfig::configure(meta, advices[0], advices[1], advices[2], advices[3]);

        Self {
            note_conifg,
            advices,
            instances,
            get_target_variable_config,
        }
    }
}

impl IntentAppValidityPredicateCircuit {
    #![allow(dead_code)]
    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let spend_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let is_spend_note = pallas::Base::zero();
        // let dealer_intent_vp_vk = ValidityPredicateVerifyingKey::dummy(&mut rng);
        Self {
            spend_notes,
            output_notes,
            is_spend_note,
            // dealer_intent_vp_vk,
        }
    }
}

impl ValidityPredicateInfo for IntentAppValidityPredicateCircuit {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        let mut instances = self.get_note_instances();

        instances.push(self.is_spend_note);

        // TODO: add dealer intent vp commitment

        instances
    }

    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
        let instance = self.get_instances();
        let proof = Proof::create(&pk, params, self.clone(), &[&instance], &mut rng).unwrap();
        VPVerifyingInfo {
            vk,
            proof,
            instance,
        }
    }

    fn get_vp_description(&self) -> ValidityPredicateVerifyingKey {
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
    }
}

impl ValidityPredicateCircuit for IntentAppValidityPredicateCircuit {
    type VPConfig = IntentAppValidityPredicateConfig;
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::VPConfig,
        mut layouter: impl Layouter<pallas::Base>,
        spend_note_variables: &[SpendNoteVar],
        output_note_variables: &[OutputNoteVar],
    ) -> Result<(), Error> {
        let is_spend_note = assign_free_advice(
            layouter.namespace(|| "witness is_spend_note"),
            config.advices[0],
            Value::known(self.is_spend_note),
        )?;

        // publicize is_spend_note and check it outside of circuit.
        layouter.constrain_instance(is_spend_note.cell(), config.instances, 2 * NUM_NOTE)?;

        // search target note and output the app_data_dynamic
        // Since there is only one user intent vp in app_data_dynamic, we don't need the app_data_dynamic decoding constraints.
        let _dealer_intent_vp = layouter.assign_region(
            || "get target dealer intent vp",
            |mut region| {
                config
                    .get_target_variable_config
                    .assign_region(&is_spend_note, &spend_note_variables[0].app_data_dynamic, &output_note_variables[0].app_data_dynamic, 0, &mut region)
            },
        )?;

        // TODO: add dealer intent vp commitment

        Ok(())
    }
}

vp_circuit_impl!(IntentAppValidityPredicateCircuit);

#[test]
fn test_halo2_intent_app_circuit() {
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = IntentAppValidityPredicateCircuit::dummy(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
