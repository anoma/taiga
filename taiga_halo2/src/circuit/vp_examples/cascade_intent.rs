/// The intent is to show how to cascade partial transactions so they can be executed atomically.
/// In this example, Alice wants to spend three(more than the fixed NUM_NOTE) different kinds of tokens/notes simultaneously.
/// She needs to distribute the notes to two partial transactions. She can use the intent to cascade the partial transactions.
/// In the first partial transaction, she spends two notes and creates a cascade intent note to encode and check the third note info.
/// In the sencond partial transaction, she spends the cascade note and the third note.
///
use crate::{
    circuit::{
        gadgets::{
            assign_free_advice,
            target_note_variable::{get_is_input_note_flag, get_owned_note_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, GeneralVerificationValidityPredicateConfig,
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    arithmetic::Field,
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

    // TODO: Move the random function to the test mod
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let cascade_input_note = Note::dummy(&mut rng);
        let cascade_note_cm = cascade_input_note.commitment().get_x();
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        let nk = NullifierKeyContainer::random_key(&mut rng);
        let intent_note = create_intent_note(&mut rng, cascade_note_cm, rho, nk);
        let input_notes = [intent_note, cascade_input_note];
        Self {
            owned_note_pub_id: input_notes[0].get_nf().unwrap().inner(),
            input_notes,
            output_notes,
            cascade_note_cm,
        }
    }
}

impl ValidityPredicateInfo for CascadeIntentValidityPredicateCircuit {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        self.get_note_instances()
    }

    fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.owned_note_pub_id
    }
}

impl ValidityPredicateCircuit for CascadeIntentValidityPredicateCircuit {
    type VPConfig = GeneralVerificationValidityPredicateConfig;
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
                    &basic_variables.input_note_variables[1].cm_x,
                    0,
                    &mut region,
                )
            },
        )?;

        Ok(())
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
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = CascadeIntentValidityPredicateCircuit::random(&mut rng);
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
