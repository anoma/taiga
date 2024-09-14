/// The intent can be satisfied with two conditions. For instance, Alice has 5
/// BTC and desires either 1 Dolphin or 2 Monkeys. Then Alice creates an intent
/// using the "or relation".
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{assign_free_advice, assign_free_constant, poseidon_hash::poseidon_hash_gadget},
        integrity::load_resource,
        merkle_circuit::MerklePoseidonChip,
        resource_commitment::ResourceCommitChip,
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            ResourceLogicCircuit, ResourceLogicConfig, ResourceLogicPublicInputs,
            ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait, ResourceStatus,
        },
        resource_logic_examples::token::{Token, TOKEN_VK},
    },
    constant::SETUP_PARAMS_MAP,
    error::TransactionError,
    nullifier::Nullifier,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    resource_tree::ResourceExistenceWitness,
    utils::poseidon_hash_n,
    utils::read_base_field,
};
use borsh::{BorshDeserialize, BorshSerialize};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::{group::ff::PrimeField, pallas};
use rand::rngs::OsRng;
use rand::RngCore;

lazy_static! {
    pub static ref OR_RELATION_INTENT_VK: ResourceLogicVerifyingKey =
        OrRelationIntentResourceLogicCircuit::default().get_resource_logic_vk();
    pub static ref COMPRESSED_OR_RELATION_INTENT_VK: pallas::Base =
        OR_RELATION_INTENT_VK.get_compressed();
}

// OrRelationIntentResourceLogicCircuit
#[derive(Clone, Debug, Default)]
pub struct OrRelationIntentResourceLogicCircuit {
    // self_resource is the intent resource
    pub self_resource: ResourceExistenceWitness,
    // If the self_resource(intent) is an output resource, a dummy desired resource is needed.
    pub desired_resource: ResourceExistenceWitness,
    pub token_1: Token,
    pub token_2: Token,
    pub receiver_npk: pallas::Base,
    pub receiver_value: pallas::Base,
}

impl OrRelationIntentResourceLogicCircuit {
    pub fn encode_label(
        token_1: &Token,
        token_2: &Token,
        receiver_npk: pallas::Base,
        receiver_value: pallas::Base,
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
            receiver_npk,
            receiver_value,
        ])
    }

    pub fn to_bytecode(&self) -> ResourceLogicByteCode {
        ResourceLogicByteCode::new(
            ResourceLogicRepresentation::OrRelationIntent,
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

impl ResourceLogicCircuit for OrRelationIntentResourceLogicCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        self_resource: ResourceStatus,
    ) -> Result<(), Error> {
        // check
        {
            let one = assign_free_constant(
                layouter.namespace(|| "constant one"),
                config.advices[0],
                pallas::Base::one(),
            )?;
            layouter.assign_region(
                || "check label",
                |mut region| {
                    region.constrain_equal(one.cell(), self_resource.resource.is_ephemeral.cell())
                },
            )?;
        }
        // load the desired resource
        let desired_resource = {
            // Construct a merkle chip
            let merkle_chip = MerklePoseidonChip::construct(config.merkle_config);

            // Construct a resource_commit chip
            let resource_commit_chip =
                ResourceCommitChip::construct(config.resource_commit_config.clone());

            load_resource(
                layouter.namespace(|| "load the desired resource"),
                config.advices,
                resource_commit_chip,
                config.conditional_select_config,
                merkle_chip,
                &self.desired_resource,
            )?
        };

        // check self_resource and desired_resource are on the same tree
        layouter.assign_region(
            || "conditional equal: check root",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &self_resource.is_input,
                    &self_resource.resource_merkle_root,
                    &desired_resource.resource_merkle_root,
                    0,
                    &mut region,
                )
            },
        )?;

        let token_resource_logic_vk = assign_free_advice(
            layouter.namespace(|| "witness token resource_logic vk"),
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

        let receiver_npk = assign_free_advice(
            layouter.namespace(|| "witness receiver npk"),
            config.advices[0],
            Value::known(self.receiver_npk),
        )?;

        let receiver_value = assign_free_advice(
            layouter.namespace(|| "witness receiver value"),
            config.advices[0],
            Value::known(self.receiver_value),
        )?;

        // Encode the label of intent resource
        let encoded_label = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "encode label"),
            [
                token_property_1.clone(),
                token_quantity_1.clone(),
                token_property_2.clone(),
                token_quantity_2.clone(),
                token_resource_logic_vk.clone(),
                receiver_npk.clone(),
                receiver_value.clone(),
            ],
        )?;

        // check the label of intent resource
        layouter.assign_region(
            || "check label",
            |mut region| {
                region.constrain_equal(encoded_label.cell(), self_resource.resource.label.cell())
            },
        )?;

        // check the resource_logic vk of output resource
        layouter.assign_region(
            || "conditional equal: check resource_logic vk",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &self_resource.is_input,
                    &token_resource_logic_vk,
                    &desired_resource.resource.logic,
                    0,
                    &mut region,
                )
            },
        )?;

        // check npk
        layouter.assign_region(
            || "conditional equal: check npk",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &self_resource.is_input,
                    &receiver_npk,
                    &desired_resource.resource.npk,
                    0,
                    &mut region,
                )
            },
        )?;

        // check value
        layouter.assign_region(
            || "conditional equal: check value",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &self_resource.is_input,
                    &receiver_value,
                    &desired_resource.resource.value,
                    0,
                    &mut region,
                )
            },
        )?;

        // check the desired_resource is an output
        {
            let zero_constant = assign_free_constant(
                layouter.namespace(|| "constant zero"),
                config.advices[0],
                pallas::Base::zero(),
            )?;

            layouter.assign_region(
                || "conditional equal: check desired_resource is_input",
                |mut region| {
                    config.conditional_equal_config.assign_region(
                        &self_resource.is_input,
                        &zero_constant,
                        &desired_resource.is_input,
                        0,
                        &mut region,
                    )
                },
            )?;
        }

        // check the token_property and token_quantity in conditions
        layouter.assign_region(
            || "extended or relatioin",
            |mut region| {
                config.extended_or_relation_config.assign_region(
                    &self_resource.is_input,
                    (&token_property_1, &token_quantity_1),
                    (&token_property_2, &token_quantity_2),
                    (
                        &desired_resource.resource.label,
                        &desired_resource.resource.quantity,
                    ),
                    0,
                    &mut region,
                )
            },
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

resource_logic_circuit_impl!(OrRelationIntentResourceLogicCircuit);
resource_logic_verifying_info_impl!(OrRelationIntentResourceLogicCircuit);

impl BorshSerialize for OrRelationIntentResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.self_resource.serialize(writer)?;
        self.desired_resource.serialize(writer)?;

        self.token_1.serialize(writer)?;
        self.token_2.serialize(writer)?;

        writer.write_all(&self.receiver_npk.to_repr())?;
        writer.write_all(&self.receiver_value.to_repr())?;

        Ok(())
    }
}

impl BorshDeserialize for OrRelationIntentResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let self_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let desired_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let token_1 = Token::deserialize_reader(reader)?;
        let token_2 = Token::deserialize_reader(reader)?;
        let receiver_npk = read_base_field(reader)?;
        let receiver_value = read_base_field(reader)?;
        Ok(Self {
            self_resource,
            desired_resource,
            token_1,
            token_2,
            receiver_npk,
            receiver_value,
        })
    }
}

pub fn create_intent_resource<R: RngCore>(
    mut rng: R,
    token_1: &Token,
    token_2: &Token,
    receiver_npk: pallas::Base,
    receiver_value: pallas::Base,
    nk: pallas::Base,
) -> Resource {
    let label = OrRelationIntentResourceLogicCircuit::encode_label(
        token_1,
        token_2,
        receiver_npk,
        receiver_value,
    );
    let rseed = pallas::Base::random(&mut rng);
    let nonce = Nullifier::random(&mut rng);
    Resource::new_input_resource(
        *COMPRESSED_OR_RELATION_INTENT_VK,
        label,
        pallas::Base::zero(),
        1u64,
        nk,
        nonce,
        true,
        rseed,
    )
}

#[test]
fn test_halo2_or_relation_intent_resource_logic_circuit() {
    use crate::constant::RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE;
    use crate::{
        circuit::resource_logic_examples::token::COMPRESSED_TOKEN_VK,
        resource::tests::random_resource, resource_tree::ResourceMerkleTreeLeaves,
    };
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let token_1 = Token::new("token1".to_string(), 1u64);
        let token_2 = Token::new("token2".to_string(), 2u64);

        // Create an output desired resource
        let mut desired_resource = random_resource(&mut rng);
        desired_resource.kind.logic = *COMPRESSED_TOKEN_VK;
        desired_resource.kind.label = token_1.encode_name();
        desired_resource.quantity = token_1.quantity();

        let nk = pallas::Base::random(&mut rng);
        let intent_resource = create_intent_resource(
            &mut rng,
            &token_1,
            &token_2,
            desired_resource.get_npk(),
            desired_resource.value,
            nk,
        );

        // Collect resource merkle leaves
        let input_resource_nf_1 = intent_resource.get_nf().unwrap().inner();
        let output_resource_cm_1 = desired_resource.commitment().inner();
        let resource_merkle_tree =
            ResourceMerkleTreeLeaves::new(vec![input_resource_nf_1, output_resource_cm_1]);

        let intent_resource_witness = {
            let merkle_path = resource_merkle_tree
                .generate_path(input_resource_nf_1)
                .unwrap();
            ResourceExistenceWitness::new(intent_resource, merkle_path)
        };

        let desired_resource_witness = {
            let merkle_path = resource_merkle_tree
                .generate_path(output_resource_cm_1)
                .unwrap();
            ResourceExistenceWitness::new(desired_resource, merkle_path)
        };

        OrRelationIntentResourceLogicCircuit {
            self_resource: intent_resource_witness,
            desired_resource: desired_resource_witness,
            token_1,
            token_2,
            receiver_npk: desired_resource.get_npk(),
            receiver_value: desired_resource.value,
        }
    };

    // Test serialization
    let circuit = {
        let circuit_bytes = circuit.to_bytes();
        OrRelationIntentResourceLogicCircuit::from_bytes(&circuit_bytes)
    };

    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover = MockProver::<pallas::Base>::run(
        RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
        &circuit,
        vec![public_inputs.to_vec()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
