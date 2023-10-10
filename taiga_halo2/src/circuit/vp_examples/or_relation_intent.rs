/// The intent can be satisfied with two conditions.
/// For example, Alice has 5 BTC and wants 1 Dolphin or 2 Monkeys.
/// Then Alice creates an intent with the "or relaiton".
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            assign_free_advice,
            poseidon_hash::poseidon_hash_gadget,
            target_note_variable::{get_is_input_note_flag, get_owned_note_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
        vp_examples::token::{transfrom_token_name_to_token_property, TOKEN_VK},
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
    utils::poseidon_hash_n,
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
    pub static ref OR_RELATION_INTENT_VK: ValidityPredicateVerifyingKey =
        OrRelationIntentValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_OR_RELATION_INTENT_VK: pallas::Base =
        OR_RELATION_INTENT_VK.get_compressed();
}

// Token swap condition
#[derive(Clone, Debug, Default)]
pub struct Condition {
    pub token_name: String,
    pub token_value: u64,
}

// OrRelationIntentValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct OrRelationIntentValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
    pub condition1: Condition,
    pub condition2: Condition,
    pub receiver_nk_com: pallas::Base,
    pub receiver_app_data_dynamic: pallas::Base,
}

impl OrRelationIntentValidityPredicateCircuit {
    pub fn encode_app_data_static(
        condition1: &Condition,
        condition2: &Condition,
        receiver_nk_com: pallas::Base,
        receiver_app_data_dynamic: pallas::Base,
    ) -> pallas::Base {
        let token_property_1 = transfrom_token_name_to_token_property(&condition1.token_name);
        let token_value_1 = pallas::Base::from(condition1.token_value);
        let token_property_2 = transfrom_token_name_to_token_property(&condition2.token_name);
        let token_value_2 = pallas::Base::from(condition2.token_value);
        poseidon_hash_n([
            token_property_1,
            token_value_1,
            token_property_2,
            token_value_2,
            TOKEN_VK.get_compressed(),
            receiver_nk_com,
            receiver_app_data_dynamic,
        ])
    }
}

impl ValidityPredicateCircuit for OrRelationIntentValidityPredicateCircuit {
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

        let token_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness token vp vk"),
            config.advices[0],
            Value::known(TOKEN_VK.get_compressed()),
        )?;

        let token_property_1 = assign_free_advice(
            layouter.namespace(|| "witness token name in condition1"),
            config.advices[0],
            Value::known(transfrom_token_name_to_token_property(
                &self.condition1.token_name,
            )),
        )?;

        let token_value_1 = assign_free_advice(
            layouter.namespace(|| "witness token value in condition1"),
            config.advices[0],
            Value::known(pallas::Base::from(self.condition1.token_value)),
        )?;

        let token_property_2 = assign_free_advice(
            layouter.namespace(|| "witness token name in condition2"),
            config.advices[0],
            Value::known(transfrom_token_name_to_token_property(
                &self.condition2.token_name,
            )),
        )?;

        let token_value_2 = assign_free_advice(
            layouter.namespace(|| "witness token value in condition2"),
            config.advices[0],
            Value::known(pallas::Base::from(self.condition2.token_value)),
        )?;

        let receiver_nk_com = assign_free_advice(
            layouter.namespace(|| "witness receiver nk_com"),
            config.advices[0],
            Value::known(self.receiver_nk_com),
        )?;

        let receiver_app_data_dynamic = assign_free_advice(
            layouter.namespace(|| "witness receiver app_data_dynamic"),
            config.advices[0],
            Value::known(self.receiver_app_data_dynamic),
        )?;

        // Encode the app_data_static of intent note
        let encoded_app_data_static = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "encode app_data_static"),
            [
                token_property_1.clone(),
                token_value_1.clone(),
                token_property_2.clone(),
                token_value_2.clone(),
                token_vp_vk.clone(),
                receiver_nk_com.clone(),
                receiver_app_data_dynamic.clone(),
            ],
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
            |mut region| {
                region.constrain_equal(encoded_app_data_static.cell(), app_data_static.cell())
            },
        )?;

        // check the vp vk of output note
        layouter.assign_region(
            || "conditional equal: check vp vk",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_note,
                    &token_vp_vk,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .app_vk,
                    0,
                    &mut region,
                )
            },
        )?;

        // check nk_com
        layouter.assign_region(
            || "conditional equal: check nk_com",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_note,
                    &receiver_nk_com,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .nk_com,
                    0,
                    &mut region,
                )
            },
        )?;

        // check app_data_dynamic
        layouter.assign_region(
            || "conditional equal: check app_data_dynamic",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_note,
                    &receiver_app_data_dynamic,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .app_data_dynamic,
                    0,
                    &mut region,
                )
            },
        )?;

        // check the token_property and token_value in conditions
        let output_note_token_property = &basic_variables.output_note_variables[0]
            .note_variables
            .app_data_static;
        let output_note_token_value = &basic_variables.output_note_variables[0]
            .note_variables
            .value;
        layouter.assign_region(
            || "extended or relatioin",
            |mut region| {
                config.extended_or_relation_config.assign_region(
                    &is_input_note,
                    (&token_property_1, &token_value_1),
                    (&token_property_2, &token_value_2),
                    (output_note_token_property, output_note_token_value),
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

vp_circuit_impl!(OrRelationIntentValidityPredicateCircuit);
vp_verifying_info_impl!(OrRelationIntentValidityPredicateCircuit);

pub fn create_intent_note<R: RngCore>(
    mut rng: R,
    condition1: &Condition,
    condition2: &Condition,
    receiver_nk_com: pallas::Base,
    receiver_app_data_dynamic: pallas::Base,
    rho: Nullifier,
    nk: NullifierKeyContainer,
) -> Note {
    let app_data_static = OrRelationIntentValidityPredicateCircuit::encode_app_data_static(
        condition1,
        condition2,
        receiver_nk_com,
        receiver_app_data_dynamic,
    );
    let rseed = RandomSeed::random(&mut rng);
    Note::new(
        *COMPRESSED_OR_RELATION_INTENT_VK,
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
fn test_halo2_or_relation_intent_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use crate::{
        circuit::vp_examples::token::COMPRESSED_TOKEN_VK, note::tests::random_output_note,
        nullifier::tests::random_nullifier,
    };
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let mut output_notes = [(); NUM_NOTE].map(|_| {
            let padding_rho = random_nullifier(&mut rng);
            random_output_note(&mut rng, padding_rho)
        });
        let condition1 = Condition {
            token_name: "token1".to_string(),
            token_value: 1u64,
        };
        let condition2 = Condition {
            token_name: "token2".to_string(),
            token_value: 2u64,
        };
        output_notes[0].note_type.app_vk = *COMPRESSED_TOKEN_VK;
        output_notes[0].note_type.app_data_static =
            transfrom_token_name_to_token_property(&condition1.token_name);
        output_notes[0].value = condition1.token_value;

        let rho = Nullifier::from(pallas::Base::random(&mut rng));
        let nk = NullifierKeyContainer::random_key(&mut rng);
        let nk_com = output_notes[0].get_nk_commitment();
        let intent_note = create_intent_note(
            &mut rng,
            &condition1,
            &condition2,
            nk_com,
            output_notes[0].app_data_dynamic,
            rho,
            nk,
        );
        let padding_input_note = Note::random_padding_input_note(&mut rng);
        let input_notes = [intent_note, padding_input_note];
        OrRelationIntentValidityPredicateCircuit {
            owned_note_pub_id: input_notes[0].get_nf().unwrap().inner(),
            input_notes,
            output_notes,
            condition1,
            condition2,
            receiver_nk_com: nk_com,
            receiver_app_data_dynamic: output_notes[0].app_data_dynamic,
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
