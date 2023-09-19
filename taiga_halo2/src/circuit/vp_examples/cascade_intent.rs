/// The intent is to show how to cascade partial transactions so they can be executed atomically.
/// In this example, Alice wants to spend three(more than the fixed NUM_NOTE) different kinds of tokens/notes simultaneously.
/// She needs to distribute the notes to two partial transactions. She can use the intent to cascade the partial transactions.
/// In the first partial transaction, she spends two notes and creates a cascade intent note to encode and check the third note info.
/// In the sencond partial transaction, she spends the cascade note and the third note.
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            assign_free_advice,
            target_note_variable::{get_is_input_note_flag, get_owned_note_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

lazy_static! {
    pub static ref CASCADE_INTENT_VK: ValidityPredicateVerifyingKey =
        CascadeIntentValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_CASCADE_INTENT_VK: pallas::Base = CASCADE_INTENT_VK.get_compressed();
}

// CascadeIntentValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct CascadeIntentValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
    // use the note commitment to identify the note.
    pub cascade_note_cm: pallas::Base,
}

impl CascadeIntentValidityPredicateCircuit {
    // We can encode at most three notes to app_data_static if needed.
    pub fn encode_app_data_static(cascade_note_cm: pallas::Base) -> pallas::Base {
        cascade_note_cm
    }
}

impl ValidityPredicateCircuit for CascadeIntentValidityPredicateCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        let owned_note_pub_id = basic_variables.get_owned_note_pub_id();
        let is_input_note = get_is_input_note_flag(
            config.get_is_input_note_flag_config,
            layouter.namespace(|| "get is_input_note_flag"),
            &owned_note_pub_id,
            &basic_variables.get_input_note_nfs(),
            &basic_variables.get_output_note_cms(),
        )?;

        // If the number of cascade notes is more than one, encode them.
        let cascade_note_cm = assign_free_advice(
            layouter.namespace(|| "witness cascade_note_cm"),
            config.advices[0],
            Value::known(self.cascade_note_cm),
        )?;

        // search target note and get the intent app_static_data
        let app_data_static = get_owned_note_variable(
            config.get_owned_note_variable_config,
            layouter.namespace(|| "get owned note app_data_static"),
            &owned_note_pub_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // check the app_data_static of intent note
        layouter.assign_region(
            || "check app_data_static",
            |mut region| region.constrain_equal(cascade_note_cm.cell(), app_data_static.cell()),
        )?;

        // check the cascade note
        layouter.assign_region(
            || "conditional equal: check the cascade note",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_note,
                    &app_data_static,
                    &basic_variables.input_note_variables[1].cm,
                    0,
                    &mut region,
                )
            },
        )?;

        // Publicize the dynamic vp commitments with default value
        publicize_default_dynamic_vp_commitments(
            &mut layouter,
            config.advices[0],
            config.instances,
        )?;

        Ok(())
    }

    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let default_vp_cm: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
        public_inputs.extend(default_vp_cm);
        public_inputs.extend(default_vp_cm);
        let padding = ValidityPredicatePublicInputs::get_public_input_padding(
            public_inputs.len(),
            &RandomSeed::random(&mut rng),
        );
        public_inputs.extend(padding);
        public_inputs.into()
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

vp_circuit_impl!(CascadeIntentValidityPredicateCircuit);

pub fn create_intent_note<R: RngCore>(
    mut rng: R,
    cascade_note_cm: pallas::Base,
    rho: Nullifier,
    nk: NullifierKeyContainer,
) -> Note {
    let app_data_static =
        CascadeIntentValidityPredicateCircuit::encode_app_data_static(cascade_note_cm);
    let rseed = RandomSeed::random(&mut rng);
    Note::new(
        *COMPRESSED_CASCADE_INTENT_VK,
        app_data_static,
        pallas::Base::zero(),
        1u64,
        nk,
        rho,
        false,
        rseed,
    )
}

#[test]
fn test_halo2_cascade_intent_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use crate::note::tests::{random_input_note, random_output_note};
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let cascade_input_note = random_input_note(&mut rng);
        let cascade_note_cm = cascade_input_note.commitment().inner();
        let rho = Nullifier::from(pallas::Base::random(&mut rng));
        let nk = NullifierKeyContainer::random_key(&mut rng);
        let intent_note = create_intent_note(&mut rng, cascade_note_cm, rho, nk);
        let input_notes = [intent_note, cascade_input_note];
        let output_notes = input_notes
            .iter()
            .map(|input| random_output_note(&mut rng, input.get_nf().unwrap()))
            .collect::<Vec<_>>();

        CascadeIntentValidityPredicateCircuit {
            owned_note_pub_id: input_notes[0].get_nf().unwrap().inner(),
            input_notes,
            output_notes: output_notes.try_into().unwrap(),
            cascade_note_cm,
        }
    };
    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover = MockProver::<pallas::Base>::run(
        VP_CIRCUIT_PARAMS_SIZE,
        &circuit,
        vec![public_inputs.to_vec()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
