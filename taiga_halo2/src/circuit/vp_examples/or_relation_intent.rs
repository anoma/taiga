/// The intent can be satisfied with two conditions.
/// For example, Alice has 5 BTC and wants 1 Dolphin or 2 Monkeys.
/// Then Alice creates an intent with the "or relaiton".
///
use crate::{
    circuit::{
        gadgets::{
            assign_free_advice, assign_free_constant,
            poseidon_hash::poseidon_hash_gadget,
            target_note_variable::{get_is_input_note_flag, get_owned_note_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, GeneralVerificationValidityPredicateConfig,
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo, ValidityPredicateVerifyingInfo,
        },
        vp_examples::token::{transfrom_token_name_to_token_property, TOKEN_VK},
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::{Note, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
    proof::Proof,
    utils::poseidon_hash_n,
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
    pub receiver_address: pallas::Base,
}

impl OrRelationIntentValidityPredicateCircuit {
    pub fn encode_app_data_static(
        condition1: &Condition,
        condition2: &Condition,
        receiver_address: pallas::Base,
    ) -> pallas::Base {
        let token_property_1 = transfrom_token_name_to_token_property(&condition1.token_name);
        let token_value_1 = pallas::Base::from(condition1.token_value);
        let token_property_2 = transfrom_token_name_to_token_property(&condition2.token_name);
        let token_value_2 = pallas::Base::from(condition2.token_value);
        poseidon_hash_n::<8>([
            token_property_1,
            token_value_1,
            token_property_2,
            token_value_2,
            TOKEN_VK.get_compressed(),
            receiver_address,
            pallas::Base::zero(),
            pallas::Base::zero(),
        ])
    }
}

impl ValidityPredicateInfo for OrRelationIntentValidityPredicateCircuit {
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

impl ValidityPredicateCircuit for OrRelationIntentValidityPredicateCircuit {
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

        let receiver_address = assign_free_advice(
            layouter.namespace(|| "witness receiver address"),
            config.advices[0],
            Value::known(self.receiver_address),
        )?;

        let padding_zero = assign_free_constant(
            layouter.namespace(|| "zero"),
            config.advices[0],
            pallas::Base::zero(),
        )?;

        // Encode the app_data_static of intent note
        let encoded_app_data_static = poseidon_hash_gadget(
            config.get_note_config().poseidon_config,
            layouter.namespace(|| "encode app_data_static"),
            [
                token_property_1.clone(),
                token_value_1.clone(),
                token_property_2.clone(),
                token_value_2.clone(),
                token_vp_vk.clone(),
                receiver_address.clone(),
                padding_zero.clone(),
                padding_zero,
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

        // check the address of output note
        layouter.assign_region(
            || "conditional equal: check address",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_note,
                    &receiver_address,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .address,
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

        Ok(())
    }
}

vp_circuit_impl!(OrRelationIntentValidityPredicateCircuit);

pub fn create_intent_note<R: RngCore>(
    mut rng: R,
    condition1: &Condition,
    condition2: &Condition,
    receiver_address: pallas::Base,
    rho: Nullifier,
    nk: NullifierKeyContainer,
) -> Note {
    let app_data_static = OrRelationIntentValidityPredicateCircuit::encode_app_data_static(
        condition1,
        condition2,
        receiver_address,
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
        let receiver_address = output_notes[0].get_address();

        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        let nk = NullifierKeyContainer::random_key(&mut rng);
        let intent_note = create_intent_note(
            &mut rng,
            &condition1,
            &condition2,
            receiver_address,
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
            receiver_address,
        }
    };
    let instances = circuit.get_instances();

    let prover = MockProver::<pallas::Base>::run(12, &circuit, vec![instances]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
