/// The intent can be "partially fulfilled". For instance, Alice has 5 BTC and
/// wants 10 ETH. Alice utilizes this intent to swap a portion proportionally,
/// exchanging 2 BTC for 4 ETH and receiving back 3 BTC.
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{
            assign_free_constant,
            mul::MulChip,
            sub::{SubChip, SubInstructions},
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            BasicResourceLogicVariables, ResourceLogicCircuit, ResourceLogicConfig,
            ResourceLogicPublicInputs, ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait,
        },
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    utils::read_base_field,
};
use borsh::{BorshDeserialize, BorshSerialize};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::{group::ff::PrimeField, pallas};
use rand::rngs::OsRng;
use rand::RngCore;

pub mod swap;
pub use swap::Swap;

mod label;
use label::PartialFulfillmentIntentLabel;

lazy_static! {
    pub static ref PARTIAL_FULFILLMENT_INTENT_VK: ResourceLogicVerifyingKey =
        PartialFulfillmentIntentResourceLogicCircuit::default().get_resource_logic_vk();
    pub static ref COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK: pallas::Base =
        PARTIAL_FULFILLMENT_INTENT_VK.get_compressed();
}

// PartialFulfillmentIntentResourceLogicCircuit
#[derive(Clone, Debug, Default)]
pub struct PartialFulfillmentIntentResourceLogicCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    pub swap: Swap,
}

impl PartialFulfillmentIntentResourceLogicCircuit {
    pub fn to_bytecode(&self) -> ResourceLogicByteCode {
        ResourceLogicByteCode::new(
            ResourceLogicRepresentation::PartialFulfillmentIntent,
            self.to_bytes(),
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap()
    }
}

impl ResourceLogicCircuit for PartialFulfillmentIntentResourceLogicCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicResourceLogicVariables,
    ) -> Result<(), Error> {
        let sub_chip = SubChip::construct(config.sub_config.clone(), ());
        let mul_chip = MulChip::construct(config.mul_config.clone());

        let owned_resource_id = basic_variables.get_owned_resource_id();

        let label = self
            .swap
            .assign_label(config.advices[0], layouter.namespace(|| "assign label"))?;
        let encoded_label = label.encode(
            config.poseidon_config.clone(),
            layouter.namespace(|| "encode label"),
        )?;

        // search target resource and get the intent label
        let owned_resource_label = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource label"),
            &owned_resource_id,
            &basic_variables.get_label_searchable_pairs(),
        )?;

        // Enforce consistency of label:
        //  - as witnessed in the swap, and
        //  - as encoded in the intent resource
        layouter.assign_region(
            || "check label",
            |mut region| region.constrain_equal(encoded_label.cell(), owned_resource_label.cell()),
        )?;

        let is_input_resource = get_is_input_resource_flag(
            config.get_is_input_resource_flag_config,
            layouter.namespace(|| "get is_input_resource_flag"),
            &owned_resource_id,
            &basic_variables.get_input_resource_nfs(),
            &basic_variables.get_output_resource_cms(),
        )?;
        // Conditional checks if is_input_resource == 1
        label.is_input_resource_checks(
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
        label.is_output_resource_checks(
            &is_output_resource,
            &basic_variables,
            &config.conditional_equal_config,
            layouter.namespace(|| "is_output_resource checks"),
        )?;

        // Conditional checks if is_partial_fulfillment == 1
        label.is_partial_fulfillment_checks(
            &is_input_resource,
            &basic_variables,
            &config.conditional_equal_config,
            &sub_chip,
            &mul_chip,
            layouter.namespace(|| "is_partial_fulfillment checks"),
        )?;

        // Publicize the dynamic resource_logic commitments with default value
        publicize_default_dynamic_resource_logic_commitments(
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

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ResourceLogicPublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let default_resource_logic_cm: [pallas::Base; 2] =
            ResourceLogicCommitment::default().to_public_inputs();
        public_inputs.extend(default_resource_logic_cm);
        public_inputs.extend(default_resource_logic_cm);
        let padding = ResourceLogicPublicInputs::get_public_input_padding(
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

resource_logic_circuit_impl!(PartialFulfillmentIntentResourceLogicCircuit);
resource_logic_verifying_info_impl!(PartialFulfillmentIntentResourceLogicCircuit);

impl BorshSerialize for PartialFulfillmentIntentResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.owned_resource_id.to_repr())?;
        for input in self.input_resources.iter() {
            input.serialize(writer)?;
        }

        for output in self.output_resources.iter() {
            output.serialize(writer)?;
        }

        self.swap.serialize(writer)?;

        Ok(())
    }
}

impl BorshDeserialize for PartialFulfillmentIntentResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let owned_resource_id = read_base_field(reader)?;
        let input_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let output_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let swap = Swap::deserialize_reader(reader)?;
        Ok(Self {
            owned_resource_id,
            input_resources: input_resources.try_into().unwrap(),
            output_resources: output_resources.try_into().unwrap(),
            swap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::resource_logic_examples::{
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    };
    use crate::constant::RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE;
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

        let circuit = PartialFulfillmentIntentResourceLogicCircuit {
            owned_resource_id: intent_resource.commitment().inner(),
            input_resources,
            output_resources,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
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

        let circuit = PartialFulfillmentIntentResourceLogicCircuit {
            owned_resource_id: intent_resource.get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            swap,
        };
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
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

        let circuit = PartialFulfillmentIntentResourceLogicCircuit {
            owned_resource_id: intent_resource.get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            swap,
        };

        // Test serialization
        let circuit = {
            let circuit_bytes = circuit.to_bytes();
            PartialFulfillmentIntentResourceLogicCircuit::from_bytes(&circuit_bytes)
        };

        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        prover.assert_satisfied();
    }
}
