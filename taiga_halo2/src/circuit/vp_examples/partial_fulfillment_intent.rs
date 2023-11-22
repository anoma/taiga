/// The intent can be partially fulfilled.
/// For example, Alice has 5 BTC and wants 10 ETH.
/// Alice utilizes this intent to do a partial swap in proportion. She can exchange 2 BTC for 4 ETH and get 3 BTC back.
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            assign_free_constant,
            mul::MulChip,
            sub::{SubChip, SubInstructions},
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

pub mod swap;
pub use swap::Swap;

mod data_static;
use data_static::PartialFulfillmentIntentDataStatic;

lazy_static! {
    pub static ref PARTIAL_FULFILLMENT_INTENT_VK: ValidityPredicateVerifyingKey =
        PartialFulfillmentIntentValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK: pallas::Base =
        PARTIAL_FULFILLMENT_INTENT_VK.get_compressed();
}

// PartialFulfillmentIntentValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct PartialFulfillmentIntentValidityPredicateCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    pub swap: Swap,
}

impl ValidityPredicateCircuit for PartialFulfillmentIntentValidityPredicateCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        let sub_chip = SubChip::construct(config.sub_config.clone(), ());
        let mul_chip = MulChip::construct(config.mul_config.clone());

        let owned_resource_id = basic_variables.get_owned_resource_id();

        let app_data_static = self.swap.assign_app_data_static(
            config.advices[0],
            layouter.namespace(|| "assign app_data_static"),
        )?;
        let encoded_app_data_static = app_data_static.encode(
            config.poseidon_config.clone(),
            layouter.namespace(|| "encode app_data_static"),
        )?;

        // search target resource and get the intent app_static_data
        let owned_resource_app_data_static = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource app_data_static"),
            &owned_resource_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // Enforce consistency of app_data_static:
        //  - as witnessed in the swap, and
        //  - as encoded in the intent resource
        layouter.assign_region(
            || "check app_data_static",
            |mut region| {
                region.constrain_equal(
                    encoded_app_data_static.cell(),
                    owned_resource_app_data_static.cell(),
                )
            },
        )?;

        let is_input_resource = get_is_input_resource_flag(
            config.get_is_input_resource_flag_config,
            layouter.namespace(|| "get is_input_resource_flag"),
            &owned_resource_id,
            &basic_variables.get_input_resource_nfs(),
            &basic_variables.get_output_resource_cms(),
        )?;
        // Conditional checks if is_input_resource == 1
        app_data_static.is_input_resource_checks(
            &is_input_resource,
            &basic_variables,
            &config.conditional_equal_config,
            layouter.namespace(|| "is_input_resource checks"),
        )?;

        let is_output_resource = {
            let constant_one = assign_free_constant(
                layouter.namespace(|| "one"),
                config.advices[0],
                pallas::Base::one(),
            )?;
            // TODO: use a nor gate to replace the sub gate.
            SubInstructions::sub(
                &sub_chip,
                layouter.namespace(|| "expected_sold_quantity - returned_quantity"),
                &is_input_resource,
                &constant_one,
            )?
        };
        // Conditional checks if is_output_resource == 1
        app_data_static.is_output_resource_checks(
            &is_output_resource,
            &basic_variables,
            &config.conditional_equal_config,
            layouter.namespace(|| "is_output_resource checks"),
        )?;

        // Conditional checks if is_partial_fulfillment == 1
        app_data_static.is_partial_fulfillment_checks(
            &is_input_resource,
            &basic_variables,
            &config.conditional_equal_config,
            &sub_chip,
            &mul_chip,
            layouter.namespace(|| "is_partial_fulfillment checks"),
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

vp_circuit_impl!(PartialFulfillmentIntentValidityPredicateCircuit);
vp_verifying_info_impl!(PartialFulfillmentIntentValidityPredicateCircuit);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::vp_examples::{
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    };
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;
    use rand::RngCore;

    // Generate a swap, along with its corresponding intent resource and authorisation
    fn swap(mut rng: impl RngCore, sell: Token, buy: Token) -> Swap {
        let sk = pallas::Scalar::random(&mut rng);
        let auth = TokenAuthorization::from_sk_vk(&sk, &COMPRESSED_TOKEN_AUTH_VK);

        Swap::random(&mut rng, sell, buy, auth)
    }

    #[test]
    fn create_intent() {
        let mut rng = OsRng;
        let sell = Token::new("token1".to_string(), 2u64);
        let buy = Token::new("token2".to_string(), 4u64);

        let swap = swap(&mut rng, sell, buy);
        let intent_resource = swap.create_intent_resource(&mut rng);

        let input_padding_resource = Resource::random_padding_resource(&mut rng);
        let output_padding_resource = Resource::random_padding_resource(&mut rng);

        let input_resources = [*swap.sell.resource(), input_padding_resource];
        let output_resources = [intent_resource, output_padding_resource];

        let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
            owned_resource_id: intent_resource.commitment().inner(),
            input_resources,
            output_resources,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            VP_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn full_fulfillment() {
        let mut rng = OsRng;
        let sell = Token::new("token1".to_string(), 2u64);
        let buy = Token::new("token2".to_string(), 4u64);

        let swap = swap(&mut rng, sell, buy);
        let intent_resource = swap.create_intent_resource(&mut rng);

        let bob_sell = swap.buy.clone();
        let (input_resources, output_resources) = swap.fill(&mut rng, intent_resource, bob_sell);

        let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
            owned_resource_id: intent_resource.get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            VP_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn partial_fulfillment() {
        let mut rng = OsRng;
        let sell = Token::new("token1".to_string(), 2u64);
        let buy = Token::new("token2".to_string(), 4u64);

        let swap = swap(&mut rng, sell, buy);
        let intent_resource = swap.create_intent_resource(&mut rng);

        let bob_sell = Token::new(swap.buy.name().inner().to_string(), 2u64);
        let (input_resources, output_resources) = swap.fill(&mut rng, intent_resource, bob_sell);

        let circuit = PartialFulfillmentIntentValidityPredicateCircuit {
            owned_resource_id: intent_resource.get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            VP_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }
}
