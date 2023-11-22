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
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
        vp_examples::token::{Token, TOKEN_VK},
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    nullifier::Nullifier,
    proof::Proof,
    resource::{RandomSeed, Resource},
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

// OrRelationIntentValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct OrRelationIntentValidityPredicateCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    pub token_1: Token,
    pub token_2: Token,
    pub receiver_nk_com: pallas::Base,
    pub receiver_app_data_dynamic: pallas::Base,
}

impl OrRelationIntentValidityPredicateCircuit {
    pub fn encode_app_data_static(
        token_1: &Token,
        token_2: &Token,
        receiver_nk_com: pallas::Base,
        receiver_app_data_dynamic: pallas::Base,
    ) -> pallas::Base {
        let token_property_1 = token_1.encode_name();
        let token_quantity_1 = token_1.encode_quantity();
        let token_property_2 = token_2.encode_name();
        let token_quantity_2 = token_2.encode_quantity();
        poseidon_hash_n([
            token_property_1,
            token_quantity_1,
            token_property_2,
            token_quantity_2,
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
        let owned_resource_id = basic_variables.get_owned_resource_id();
        let is_input_resource = get_is_input_resource_flag(
            config.get_is_input_resource_flag_config,
            layouter.namespace(|| "get is_input_resource_flag"),
            &owned_resource_id,
            &basic_variables.get_input_resource_nfs(),
            &basic_variables.get_output_resource_cms(),
        )?;

        let token_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness token vp vk"),
            config.advices[0],
            Value::known(TOKEN_VK.get_compressed()),
        )?;

        let token_property_1 = assign_free_advice(
            layouter.namespace(|| "witness token name in token_1"),
            config.advices[0],
            Value::known(self.token_1.encode_name()),
        )?;

        let token_quantity_1 = assign_free_advice(
            layouter.namespace(|| "witness token quantity in token_1"),
            config.advices[0],
            Value::known(self.token_1.encode_quantity()),
        )?;

        let token_property_2 = assign_free_advice(
            layouter.namespace(|| "witness token name in token_2"),
            config.advices[0],
            Value::known(self.token_2.encode_name()),
        )?;

        let token_quantity_2 = assign_free_advice(
            layouter.namespace(|| "witness token quantity in token_2"),
            config.advices[0],
            Value::known(self.token_2.encode_quantity()),
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

        // Encode the app_data_static of intent resource
        let encoded_app_data_static = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "encode app_data_static"),
            [
                token_property_1.clone(),
                token_quantity_1.clone(),
                token_property_2.clone(),
                token_quantity_2.clone(),
                token_vp_vk.clone(),
                receiver_nk_com.clone(),
                receiver_app_data_dynamic.clone(),
            ],
        )?;

        // search target resource and get the intent app_static_data
        let app_data_static = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource app_data_static"),
            &owned_resource_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // check the app_data_static of intent resource
        layouter.assign_region(
            || "check app_data_static",
            |mut region| {
                region.constrain_equal(encoded_app_data_static.cell(), app_data_static.cell())
            },
        )?;

        // check the vp vk of output resource
        layouter.assign_region(
            || "conditional equal: check vp vk",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_resource,
                    &token_vp_vk,
                    &basic_variables.output_resource_variables[0]
                        .resource_variables
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
                    &is_input_resource,
                    &receiver_nk_com,
                    &basic_variables.output_resource_variables[0]
                        .resource_variables
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
                    &is_input_resource,
                    &receiver_app_data_dynamic,
                    &basic_variables.output_resource_variables[0]
                        .resource_variables
                        .app_data_dynamic,
                    0,
                    &mut region,
                )
            },
        )?;

        // check the token_property and token_quantity in conditions
        let output_resource_token_property = &basic_variables.output_resource_variables[0]
            .resource_variables
            .app_data_static;
        let output_resource_token_quantity = &basic_variables.output_resource_variables[0]
            .resource_variables
            .quantity;
        layouter.assign_region(
            || "extended or relatioin",
            |mut region| {
                config.extended_or_relation_config.assign_region(
                    &is_input_resource,
                    (&token_property_1, &token_quantity_1),
                    (&token_property_2, &token_quantity_2),
                    (
                        output_resource_token_property,
                        output_resource_token_quantity,
                    ),
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

    fn get_input_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.input_resources
    }

    fn get_output_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.output_resources
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

    fn get_owned_resource_id(&self) -> pallas::Base {
        self.owned_resource_id
    }
}

vp_circuit_impl!(OrRelationIntentValidityPredicateCircuit);
vp_verifying_info_impl!(OrRelationIntentValidityPredicateCircuit);

pub fn create_intent_resource<R: RngCore>(
    mut rng: R,
    token_1: &Token,
    token_2: &Token,
    receiver_nk_com: pallas::Base,
    receiver_app_data_dynamic: pallas::Base,
    nk: pallas::Base,
) -> Resource {
    let app_data_static = OrRelationIntentValidityPredicateCircuit::encode_app_data_static(
        token_1,
        token_2,
        receiver_nk_com,
        receiver_app_data_dynamic,
    );
    let rseed = RandomSeed::random(&mut rng);
    let rho = Nullifier::random(&mut rng);
    Resource::new_input_resource(
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
        circuit::vp_examples::token::COMPRESSED_TOKEN_VK, resource::tests::random_resource,
    };
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let mut output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let token_1 = Token::new("token1".to_string(), 1u64);
        let token_2 = Token::new("token2".to_string(), 2u64);
        output_resources[0].kind.app_vk = *COMPRESSED_TOKEN_VK;
        output_resources[0].kind.app_data_static = token_1.encode_name();
        output_resources[0].quantity = token_1.quantity();

        let nk = pallas::Base::random(&mut rng);
        let nk_com = output_resources[0].get_nk_commitment();
        let intent_resource = create_intent_resource(
            &mut rng,
            &token_1,
            &token_2,
            nk_com,
            output_resources[0].app_data_dynamic,
            nk,
        );
        let padding_input_resource = Resource::random_padding_resource(&mut rng);
        let input_resources = [intent_resource, padding_input_resource];
        OrRelationIntentValidityPredicateCircuit {
            owned_resource_id: input_resources[0].get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            token_1,
            token_2,
            receiver_nk_com: nk_com,
            receiver_app_data_dynamic: output_resources[0].app_data_dynamic,
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
