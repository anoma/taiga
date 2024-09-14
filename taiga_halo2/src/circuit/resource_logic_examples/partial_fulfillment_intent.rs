/// The intent can be "partially fulfilled". For instance, Alice has 5 BTC(sell_resource) and
/// wants 10 ETH. Alice utilizes this intent to swap a portion proportionally,
/// exchanging 2 BTC for 4 ETH(offer resource) and receiving back 3 BTC(returned resource).
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{mul::MulChip, sub::SubChip},
        integrity::load_resource,
        merkle_circuit::MerklePoseidonChip,
        resource_commitment::ResourceCommitChip,
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            ResourceLogicCircuit, ResourceLogicConfig, ResourceLogicPublicInputs,
            ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait, ResourceStatus,
        },
    },
    constant::SETUP_PARAMS_MAP,
    error::TransactionError,
    proof::Proof,
    resource::RandomSeed,
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    resource_tree::ResourceExistenceWitness,
};
use borsh::{BorshDeserialize, BorshSerialize};
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
    // intent resource
    pub self_resource: ResourceExistenceWitness,
    // constraints on sell_resource will be enabled only when creating the intent resource, otherwise it's a dummy one
    pub sell_resource: ResourceExistenceWitness,
    // constraints will be enabled only when consuming the intent resource, otherwise it's a dummy one
    pub offer_resource: ResourceExistenceWitness,
    // constraints will be enabled only when consuming the intent resource, otherwise it's a dummy one
    pub returned_resource: ResourceExistenceWitness,
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
        self_resource: ResourceStatus,
    ) -> Result<(), Error> {
        // Construct a merkle chip
        let merkle_chip = MerklePoseidonChip::construct(config.merkle_config);

        // Construct a resource_commit chip
        let resource_commit_chip =
            ResourceCommitChip::construct(config.resource_commit_config.clone());

        let sub_chip = SubChip::construct(config.sub_config.clone(), ());
        let mul_chip = MulChip::construct(config.mul_config.clone());

        // load the sell resource
        let sell_resource = load_resource(
            layouter.namespace(|| "load the sell resource"),
            config.advices,
            resource_commit_chip.clone(),
            config.conditional_select_config,
            merkle_chip.clone(),
            &self.sell_resource,
        )?;

        // load the offer resource
        let offer_resource = load_resource(
            layouter.namespace(|| "load the offer resource"),
            config.advices,
            resource_commit_chip.clone(),
            config.conditional_select_config,
            merkle_chip.clone(),
            &self.offer_resource,
        )?;

        // load the returned resource
        let returned_resource = load_resource(
            layouter.namespace(|| "load the returned resource"),
            config.advices,
            resource_commit_chip,
            config.conditional_select_config,
            merkle_chip,
            &self.returned_resource,
        )?;

        // check: self_resource and offer_resource are on the same tree
        layouter.assign_region(
            || "conditional equal: check offer_resource root",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &self_resource.is_input,
                    &self_resource.resource_merkle_root,
                    &offer_resource.resource_merkle_root,
                    0,
                    &mut region,
                )
            },
        )?;

        let label = self
            .swap
            .assign_label(config.advices[0], layouter.namespace(|| "assign label"))?;
        let encoded_label = label.encode(
            config.poseidon_config.clone(),
            layouter.namespace(|| "encode label"),
        )?;

        // Enforce consistency of label:
        //  - as witnessed in the swap, and
        //  - as encoded in the intent resource
        layouter.assign_region(
            || "check label",
            |mut region| {
                region.constrain_equal(encoded_label.cell(), self_resource.resource.label.cell())
            },
        )?;

        // intent resource creation
        label.intent_resource_creation_check(
            &self_resource,
            &sell_resource,
            &config.advices,
            &config.conditional_equal_config,
            &sub_chip,
            layouter.namespace(|| "intent resource creation"),
        )?;

        // intent resource consumption
        label.intent_resource_consumption_check(
            &self_resource.is_input,
            &offer_resource,
            &config.conditional_equal_config,
            layouter.namespace(|| "intent resource consumption"),
        )?;

        label.partial_fulfillment_check(
            &self_resource,
            &offer_resource,
            &returned_resource,
            &config.conditional_equal_config,
            &sub_chip,
            &mul_chip,
            layouter.namespace(|| "partial fulfillment check"),
        )?;

        // Publicize the dynamic resource_logic commitments with default value
        publicize_default_dynamic_resource_logic_commitments(
            &mut layouter,
            config.advices[0],
            config.instances,
        )?;

        Ok(())
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

    fn get_self_resource(&self) -> ResourceExistenceWitness {
        self.self_resource
    }
}

resource_logic_circuit_impl!(PartialFulfillmentIntentResourceLogicCircuit);
resource_logic_verifying_info_impl!(PartialFulfillmentIntentResourceLogicCircuit);

impl BorshSerialize for PartialFulfillmentIntentResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.self_resource.serialize(writer)?;
        self.sell_resource.serialize(writer)?;
        self.offer_resource.serialize(writer)?;
        self.returned_resource.serialize(writer)?;
        self.swap.serialize(writer)?;

        Ok(())
    }
}

impl BorshDeserialize for PartialFulfillmentIntentResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let self_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let sell_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let offer_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let returned_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let swap = Swap::deserialize_reader(reader)?;
        Ok(Self {
            self_resource,
            sell_resource,
            offer_resource,
            returned_resource,
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
    use crate::resource_tree::ResourceMerkleTreeLeaves;
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
        let sell_resource = swap.sell.resource();
        let sell_nf = sell_resource.get_nf().unwrap().inner();
        let intent_resource_cm = intent_resource.commitment().inner();
        let resource_merkle_tree = ResourceMerkleTreeLeaves::new(vec![sell_nf, intent_resource_cm]);

        let sell_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(sell_nf).unwrap();
            ResourceExistenceWitness::new(*sell_resource, merkle_path)
        };

        let intent_resource_witness = {
            let merkle_path = resource_merkle_tree
                .generate_path(intent_resource_cm)
                .unwrap();
            ResourceExistenceWitness::new(intent_resource, merkle_path)
        };

        let circuit = PartialFulfillmentIntentResourceLogicCircuit {
            self_resource: intent_resource_witness,
            sell_resource: sell_resource_witness,
            offer_resource: ResourceExistenceWitness::default(), // a dummy resource
            returned_resource: ResourceExistenceWitness::default(), // a dummy resource
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
        let (offer_resource, _returned_resource) = swap.fill(&mut rng, bob_sell);

        let intent_nf = intent_resource.get_nf().unwrap().inner();
        let offer_cm = offer_resource.commitment().inner();
        let resource_merkle_tree = ResourceMerkleTreeLeaves::new(vec![intent_nf, offer_cm]);

        let intent_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(intent_nf).unwrap();
            ResourceExistenceWitness::new(intent_resource, merkle_path)
        };

        let offer_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(offer_cm).unwrap();
            ResourceExistenceWitness::new(offer_resource, merkle_path)
        };

        let circuit = PartialFulfillmentIntentResourceLogicCircuit {
            self_resource: intent_resource_witness,
            sell_resource: ResourceExistenceWitness::default(), // a dummy one
            offer_resource: offer_resource_witness,
            returned_resource: ResourceExistenceWitness::default(), // a dummy one
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
        let (offer_resource, returned_resource) = swap.fill(&mut rng, bob_sell);

        let intent_nf = intent_resource.get_nf().unwrap().inner();
        let offer_cm = offer_resource.commitment().inner();
        let returned_cm = returned_resource.commitment().inner();
        let resource_merkle_tree = ResourceMerkleTreeLeaves::new(vec![
            intent_nf,
            offer_cm,
            pallas::Base::zero(),
            returned_cm,
        ]);

        let intent_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(intent_nf).unwrap();
            ResourceExistenceWitness::new(intent_resource, merkle_path)
        };

        let offer_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(offer_cm).unwrap();
            ResourceExistenceWitness::new(offer_resource, merkle_path)
        };

        let returned_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(returned_cm).unwrap();
            ResourceExistenceWitness::new(returned_resource, merkle_path)
        };

        let circuit = PartialFulfillmentIntentResourceLogicCircuit {
            self_resource: intent_resource_witness,
            sell_resource: ResourceExistenceWitness::default(), // a dummy one
            offer_resource: offer_resource_witness,
            returned_resource: returned_resource_witness,
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
