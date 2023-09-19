/// The intent can be partially fulfilled.
/// For example, Alice has 5 BTC and wants 10 ETH.
/// Alice utilizes this intent to do a partial swap in proportion. She can exchange 2 BTC for 4 ETH and get 3 BTC back.
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            assign_free_advice, assign_free_constant,
            mul::{MulChip, MulInstructions},
            poseidon_hash::poseidon_hash_gadget,
            sub::{SubChip, SubInstructions},
            target_note_variable::{get_is_input_note_flag, get_owned_note_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
        vp_examples::token::{transfrom_token_name_to_token_property, Token, TOKEN_VK},
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
    pub static ref PARTIAL_FULFILLMENT_INTENT_VK: ValidityPredicateVerifyingKey =
        PartialFulfillmentIntentValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK: pallas::Base =
        PARTIAL_FULFILLMENT_INTENT_VK.get_compressed();
}
// PartialFulfillmentIntentValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct PartialFulfillmentIntentValidityPredicateCircuit {
    pub owned_note_pub_id: pallas::Base,
    pub input_notes: [Note; NUM_NOTE],
    pub output_notes: [Note; NUM_NOTE],
    pub sell: Token,
    pub buy: Token,
    pub receiver_nk_com: pallas::Base,
    pub receiver_app_data_dynamic: pallas::Base,
}

impl PartialFulfillmentIntentValidityPredicateCircuit {
    pub fn encode_app_data_static(
        sell: &Token,
        buy: &Token,
        receiver_nk_com: pallas::Base,
        receiver_app_data_dynamic: pallas::Base,
    ) -> pallas::Base {
        let sold_token = transfrom_token_name_to_token_property(&sell.name);
        let sold_token_value = pallas::Base::from(sell.value);
        let bought_token = transfrom_token_name_to_token_property(&buy.name);
        let bought_token_value = pallas::Base::from(buy.value);
        poseidon_hash_n([
            sold_token,
            sold_token_value,
            bought_token,
            bought_token_value,
            // Assuming the sold_token and bought_token have the same TOKEN_VK
            TOKEN_VK.get_compressed(),
            receiver_nk_com,
            receiver_app_data_dynamic,
        ])
    }
}

impl ValidityPredicateCircuit for PartialFulfillmentIntentValidityPredicateCircuit {
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

        let sold_token = assign_free_advice(
            layouter.namespace(|| "witness sold_token"),
            config.advices[0],
            Value::known(transfrom_token_name_to_token_property(&self.sell.name)),
        )?;

        let sold_token_value = assign_free_advice(
            layouter.namespace(|| "witness sold_token_value"),
            config.advices[0],
            Value::known(pallas::Base::from(self.sell.value)),
        )?;

        let bought_token = assign_free_advice(
            layouter.namespace(|| "witness bought_token"),
            config.advices[0],
            Value::known(transfrom_token_name_to_token_property(&self.buy.name)),
        )?;

        let bought_token_value = assign_free_advice(
            layouter.namespace(|| "witness bought_token_value"),
            config.advices[0],
            Value::known(pallas::Base::from(self.buy.value)),
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
            layouter.namespace(|| "app_data_static encoding"),
            [
                sold_token.clone(),
                sold_token_value.clone(),
                bought_token.clone(),
                bought_token_value.clone(),
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

        // Create the intent note
        {
            // TODO: use a nor gate to replace the sub gate.
            let sub_chip = SubChip::construct(config.sub_config.clone(), ());
            let constant_one = assign_free_constant(
                layouter.namespace(|| "one"),
                config.advices[0],
                pallas::Base::one(),
            )?;
            let is_output_note = SubInstructions::sub(
                &sub_chip,
                layouter.namespace(|| "expected_sold_value - returned_value"),
                &is_input_note,
                &constant_one,
            )?;
            layouter.assign_region(
                || "conditional equal: check sold token vp_vk",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_output_note,
                        &token_vp_vk,
                        &basic_variables.input_note_variables[0]
                            .note_variables
                            .app_vk,
                        0,
                        &mut region,
                    )
                },
            )?;

            layouter.assign_region(
                || "conditional equal: check sold token app_data_static",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_output_note,
                        &sold_token,
                        &basic_variables.input_note_variables[0]
                            .note_variables
                            .app_data_static,
                        0,
                        &mut region,
                    )
                },
            )?;

            layouter.assign_region(
                || "conditional equal: check sold token value",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_output_note,
                        &sold_token_value,
                        &basic_variables.input_note_variables[0].note_variables.value,
                        0,
                        &mut region,
                    )
                },
            )?;
        }

        // Consume the intent note
        {
            layouter.assign_region(
                || "conditional equal: check bought token vk",
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

            layouter.assign_region(
                || "conditional equal: check bought token vk",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_input_note,
                        &bought_token,
                        &basic_variables.output_note_variables[0]
                            .note_variables
                            .app_data_static,
                        0,
                        &mut region,
                    )
                },
            )?;

            // check nk_com
            layouter.assign_region(
                || "conditional equal: check bought token nk_com",
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
                || "conditional equal: check bought token app_data_dynamic",
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

            let sub_chip = SubChip::construct(config.sub_config, ());
            let mul_chip = MulChip::construct(config.mul_config);

            let is_partial_fulfillment = SubInstructions::sub(
                &sub_chip,
                layouter.namespace(|| "expected_bought_token_value - actual_bought_token_value"),
                &bought_token_value,
                &basic_variables.output_note_variables[0]
                    .note_variables
                    .value,
            )?;
            let is_partial_fulfillment = MulInstructions::mul(
                &mul_chip,
                layouter.namespace(|| "is_input * is_partial_fulfillment"),
                &is_input_note,
                &is_partial_fulfillment,
            )?;

            // check returned token vk if it's partially fulfilled
            layouter.assign_region(
                || "conditional equal: check returned token vk",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_partial_fulfillment,
                        &token_vp_vk,
                        &basic_variables.output_note_variables[1]
                            .note_variables
                            .app_vk,
                        0,
                        &mut region,
                    )
                },
            )?;

            // check return token app_data_static if it's partially fulfilled
            layouter.assign_region(
                || "conditional equal: check returned token app_data_static",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_partial_fulfillment,
                        &sold_token,
                        &basic_variables.output_note_variables[1]
                            .note_variables
                            .app_data_static,
                        0,
                        &mut region,
                    )
                },
            )?;

            layouter.assign_region(
                || "conditional equal: check returned token nk_com",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_partial_fulfillment,
                        &receiver_nk_com,
                        &basic_variables.output_note_variables[1]
                            .note_variables
                            .nk_com,
                        0,
                        &mut region,
                    )
                },
            )?;

            layouter.assign_region(
                || "conditional equal: check returned token app_data_dynamic",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &is_partial_fulfillment,
                        &receiver_app_data_dynamic,
                        &basic_variables.output_note_variables[1]
                            .note_variables
                            .app_data_dynamic,
                        0,
                        &mut region,
                    )
                },
            )?;

            // value check
            {
                let actual_sold_value = SubInstructions::sub(
                    &sub_chip,
                    layouter.namespace(|| "expected_sold_value - returned_value"),
                    &sold_token_value,
                    &basic_variables.output_note_variables[1]
                        .note_variables
                        .value,
                )?;

                // check (expected_bought_value * actual_sold_value) == (expected_sold_value * actual_bought_value)
                // if it's partially fulfilled
                let expected_bought_mul_actual_sold_value = MulInstructions::mul(
                    &mul_chip,
                    layouter.namespace(|| "expected_bought_value * actual_sold_value"),
                    &bought_token_value,
                    &actual_sold_value,
                )?;
                let expected_sold_mul_actual_bought_value = MulInstructions::mul(
                    &mul_chip,
                    layouter.namespace(|| "expected_sold_value * actual_bought_value"),
                    &sold_token_value,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .value,
                )?;

                layouter.assign_region(
                    || "conditional equal: expected_bought_value * actual_sold_value == expected_sold_value * actual_bought_value",
                    |mut region| {
                        config.conditional_equal_config.assign_region(
                            &is_partial_fulfillment,
                            &expected_bought_mul_actual_sold_value,
                            &expected_sold_mul_actual_bought_value,
                            0,
                            &mut region,
                        )
                    },
                )?;
            }
        }

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

vp_circuit_impl!(PartialFulfillmentIntentValidityPredicateCircuit);

pub fn create_intent_note<R: RngCore>(
    mut rng: R,
    sell: &Token,
    buy: &Token,
    receiver_nk_com: pallas::Base,
    receiver_app_data_dynamic: pallas::Base,
    rho: Nullifier,
    nk: NullifierKeyContainer,
) -> Note {
    let app_data_static = PartialFulfillmentIntentValidityPredicateCircuit::encode_app_data_static(
        sell,
        buy,
        receiver_nk_com,
        receiver_app_data_dynamic,
    );
    let rseed = RandomSeed::random(&mut rng);
    Note::new(
        *COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK,
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
fn test_halo2_partial_fulfillment_intent_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use crate::{circuit::vp_examples::token::COMPRESSED_TOKEN_VK, note::tests::random_input_note};
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    let sell = Token {
        name: "token1".to_string(),
        value: 2u64,
    };
    let buy = Token {
        name: "token2".to_string(),
        value: 4u64,
    };

    let mut sold_note = random_input_note(&mut rng);
    sold_note.note_type.app_vk = *COMPRESSED_TOKEN_VK;
    sold_note.note_type.app_data_static = transfrom_token_name_to_token_property(&sell.name);
    sold_note.value = sell.value;
    let receiver_nk_com = sold_note.get_nk_commitment();
    let rho = Nullifier::new(pallas::Base::random(&mut rng));
    let nk = NullifierKeyContainer::random_key(&mut rng);
    let intent_note = create_intent_note(
        &mut rng,
        &sell,
        &buy,
        receiver_nk_com,
        sold_note.app_data_dynamic,
        rho,
        nk,
    );
    // Creating intent test
    {
        let input_padding_note = Note::random_padding_input_note(&mut rng);
        let input_notes = [sold_note, input_padding_note];
        let output_padding_note =
            Note::random_padding_output_note(&mut rng, input_padding_note.get_nf().unwrap());
        let output_notes = [intent_note, output_padding_note];

        let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
            owned_note_pub_id: intent_note.commitment().inner(),
            input_notes,
            output_notes,
            sell: sell.clone(),
            buy: buy.clone(),
            receiver_nk_com,
            receiver_app_data_dynamic: sold_note.app_data_dynamic,
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

    // Consuming intent test
    {
        {
            let input_padding_note = Note::random_padding_input_note(&mut rng);
            let input_notes = [intent_note, input_padding_note];
            let mut bought_note = sold_note;
            bought_note.note_type.app_data_static =
                transfrom_token_name_to_token_property(&buy.name);
            bought_note.app_data_dynamic = sold_note.app_data_dynamic;
            bought_note.nk_container = sold_note.nk_container;

            // full fulfillment
            {
                bought_note.value = buy.value;
                let output_padding_note = Note::random_padding_output_note(
                    &mut rng,
                    input_padding_note.get_nf().unwrap(),
                );
                let output_notes = [bought_note, output_padding_note];

                let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
                    owned_note_pub_id: intent_note.get_nf().unwrap().inner(),
                    input_notes,
                    output_notes,
                    sell: sell.clone(),
                    buy: buy.clone(),
                    receiver_nk_com,
                    receiver_app_data_dynamic: sold_note.app_data_dynamic,
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

            // partial fulfillment
            {
                bought_note.value = 2u64;
                let mut returned_note = bought_note;
                returned_note.note_type.app_data_static =
                    transfrom_token_name_to_token_property(&sell.name);
                returned_note.value = 1u64;
                let output_notes = [bought_note, returned_note];

                let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
                    owned_note_pub_id: intent_note.get_nf().unwrap().inner(),
                    input_notes,
                    output_notes,
                    sell,
                    buy,
                    receiver_nk_com,
                    receiver_app_data_dynamic: sold_note.app_data_dynamic,
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
        }
    }
}
