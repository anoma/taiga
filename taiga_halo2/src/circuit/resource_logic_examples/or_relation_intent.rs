/// The intent can be satisfied with two conditions. For instance, Alice has 5
/// BTC and desires either 1 Dolphin or 2 Monkeys. Then Alice creates an intent
/// using the "or relation".
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{
            assign_free_advice,
            poseidon_hash::poseidon_hash_gadget,
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            BasicResourceLogicVariables, ResourceLogicCircuit, ResourceLogicConfig,
            ResourceLogicPublicInputs, ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait,
        },
        resource_logic_examples::token::{Token, TOKEN_VK},
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    nullifier::Nullifier,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
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
    pub self_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
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
        basic_variables: BasicResourceLogicVariables,
    ) -> Result<(), Error> {
        let self_resource_id = basic_variables.get_self_resource_id();
        let is_input_resource = get_is_input_resource_flag(
            config.get_is_input_resource_flag_config,
            layouter.namespace(|| "get is_input_resource_flag"),
            &self_resource_id,
            &basic_variables.get_input_resource_nfs(),
            &basic_variables.get_output_resource_cms(),
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

        // search target resource and get the intent label
        let label = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource label"),
            &self_resource_id,
            &basic_variables.get_label_searchable_pairs(),
        )?;

        // check the label of intent resource
        layouter.assign_region(
            || "check label",
            |mut region| region.constrain_equal(encoded_label.cell(), label.cell()),
        )?;

        // check the resource_logic vk of output resource
        layouter.assign_region(
            || "conditional equal: check resource_logic vk",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_resource,
                    &token_resource_logic_vk,
                    &basic_variables.output_resource_variables[0]
                        .resource_variables
                        .logic,
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
                    &is_input_resource,
                    &receiver_npk,
                    &basic_variables.output_resource_variables[0]
                        .resource_variables
                        .npk,
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
                    &is_input_resource,
                    &receiver_value,
                    &basic_variables.output_resource_variables[0]
                        .resource_variables
                        .value,
                    0,
                    &mut region,
                )
            },
        )?;

        // check the token_property and token_quantity in conditions
        let output_resource_token_property = &basic_variables.output_resource_variables[0]
            .resource_variables
            .label;
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

    fn get_self_resource_id(&self) -> pallas::Base {
        self.self_resource_id
    }
}

resource_logic_circuit_impl!(OrRelationIntentResourceLogicCircuit);
resource_logic_verifying_info_impl!(OrRelationIntentResourceLogicCircuit);

impl BorshSerialize for OrRelationIntentResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.self_resource_id.to_repr())?;
        for input in self.input_resources.iter() {
            input.serialize(writer)?;
        }

        for output in self.output_resources.iter() {
            output.serialize(writer)?;
        }

        self.token_1.serialize(writer)?;
        self.token_2.serialize(writer)?;

        writer.write_all(&self.receiver_npk.to_repr())?;
        writer.write_all(&self.receiver_value.to_repr())?;

        Ok(())
    }
}

impl BorshDeserialize for OrRelationIntentResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let self_resource_id = read_base_field(reader)?;
        let input_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let output_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let token_1 = Token::deserialize_reader(reader)?;
        let token_2 = Token::deserialize_reader(reader)?;
        let receiver_npk = read_base_field(reader)?;
        let receiver_value = read_base_field(reader)?;
        Ok(Self {
            self_resource_id,
            input_resources: input_resources.try_into().unwrap(),
            output_resources: output_resources.try_into().unwrap(),
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
        resource::tests::random_resource,
    };
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let mut output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let token_1 = Token::new("token1".to_string(), 1u64);
        let token_2 = Token::new("token2".to_string(), 2u64);
        output_resources[0].kind.logic = *COMPRESSED_TOKEN_VK;
        output_resources[0].kind.label = token_1.encode_name();
        output_resources[0].quantity = token_1.quantity();

        let nk = pallas::Base::random(&mut rng);
        let npk = output_resources[0].get_npk();
        let intent_resource = create_intent_resource(
            &mut rng,
            &token_1,
            &token_2,
            npk,
            output_resources[0].value,
            nk,
        );
        let padding_input_resource = Resource::random_padding_resource(&mut rng);
        let input_resources = [intent_resource, padding_input_resource];
        OrRelationIntentResourceLogicCircuit {
            self_resource_id: input_resources[0].get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            token_1,
            token_2,
            receiver_npk: npk,
            receiver_value: output_resources[0].value,
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
