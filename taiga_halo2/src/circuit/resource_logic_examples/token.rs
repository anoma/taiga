use crate::{
    circuit::{
        blake2s::{resource_logic_commitment_gadget, Blake2sChip},
        gadgets::{assign_free_advice, assign_free_constant, poseidon_hash::poseidon_hash_gadget},
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            ResourceLogicCircuit, ResourceLogicConfig, ResourceLogicPublicInputs,
            ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait, ResourceStatus,
        },
        resource_logic_examples::receiver_resource_logic::{
            ReceiverResourceLogicCircuit, COMPRESSED_RECEIVER_VK,
        },
        resource_logic_examples::signature_verification::{
            SignatureVerificationResourceLogicCircuit, COMPRESSED_TOKEN_AUTH_VK,
        },
    },
    constant::{
        PRF_EXPAND_DYNAMIC_RESOURCE_LOGIC_1_CM_R,
        RESOURCE_LOGIC_CIRCUIT_FIRST_DYNAMIC_RESOURCE_LOGIC_CM_1,
        RESOURCE_LOGIC_CIRCUIT_FIRST_DYNAMIC_RESOURCE_LOGIC_CM_2,
        RESOURCE_LOGIC_CIRCUIT_SECOND_DYNAMIC_RESOURCE_LOGIC_CM_1,
        RESOURCE_LOGIC_CIRCUIT_SECOND_DYNAMIC_RESOURCE_LOGIC_CM_2, SETUP_PARAMS_MAP,
        TAIGA_RESOURCE_TREE_DEPTH,
    },
    error::TransactionError,
    merkle_tree::LR,
    nullifier::Nullifier,
    proof::Proof,
    resource::{RandomSeed, Resource, ResourceLogics},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    resource_tree::ResourceExistenceWitness,
    utils::{poseidon_hash_n, read_base_field, read_point},
};
use borsh::{BorshDeserialize, BorshSerialize};
use ff::Field;
use group::{Curve, Group, GroupEncoding};
use halo2_gadgets::ecc::{chip::EccChip, NonIdentityPoint};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::{group::ff::PrimeField, pallas};
use rand::{rngs::OsRng, Rng, RngCore};

lazy_static! {
    pub static ref TOKEN_VK: ResourceLogicVerifyingKey =
        TokenResourceLogicCircuit::default().get_resource_logic_vk();
    pub static ref COMPRESSED_TOKEN_VK: pallas::Base = TOKEN_VK.get_compressed();
}

#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TokenName(String);

impl TokenName {
    pub fn encode(&self) -> pallas::Base {
        assert!(self.0.len() < 32);
        let mut bytes: [u8; 32] = [0; 32];
        bytes[..self.0.len()].copy_from_slice(self.0.as_bytes());
        pallas::Base::from_repr(bytes).unwrap()
    }

    pub fn inner(&self) -> String {
        self.0.clone()
    }
}

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct Token {
    name: TokenName,
    quantity: u64,
}

impl Token {
    pub fn new(name: String, quantity: u64) -> Self {
        Self {
            name: TokenName(name),
            quantity,
        }
    }

    pub fn name(&self) -> &TokenName {
        &self.name
    }

    pub fn quantity(&self) -> u64 {
        self.quantity
    }

    pub fn encode_name(&self) -> pallas::Base {
        self.name.encode()
    }

    pub fn encode_quantity(&self) -> pallas::Base {
        pallas::Base::from(self.quantity)
    }

    pub fn create_random_input_token_resource<R: RngCore>(
        &self,
        mut rng: R,
        nk: pallas::Base,
        auth: &TokenAuthorization,
    ) -> TokenResource {
        let label = self.encode_name();
        let value = auth.to_value();
        let rseed = pallas::Base::random(&mut rng);
        let nonce = Nullifier::random(&mut rng);
        let resource = Resource::new_input_resource(
            *COMPRESSED_TOKEN_VK,
            label,
            value,
            self.quantity(),
            nk,
            nonce,
            false,
            rseed,
        );

        TokenResource {
            token_name: self.name().clone(),
            resource,
        }
    }

    pub fn create_random_output_token_resource<R: RngCore>(
        &self,
        mut rng: R,
        npk: pallas::Base,
        auth: &TokenAuthorization,
    ) -> TokenResource {
        let label = self.encode_name();
        let value = auth.to_value();
        let rseed = pallas::Base::random(&mut rng);
        let resource = Resource::new_output_resource(
            *COMPRESSED_TOKEN_VK,
            label,
            value,
            self.quantity(),
            npk,
            false,
            rseed,
        );

        TokenResource {
            token_name: self.name().clone(),
            resource,
        }
    }
}

#[derive(Clone, Debug, Default, BorshDeserialize, BorshSerialize)]
pub struct TokenResource {
    pub token_name: TokenName,
    pub resource: Resource,
}

impl std::ops::Deref for TokenResource {
    type Target = Resource;

    fn deref(&self) -> &Self::Target {
        &self.resource
    }
}

impl TokenResource {
    pub fn token_name(&self) -> &TokenName {
        &self.token_name
    }

    pub fn encode_name(&self) -> pallas::Base {
        self.token_name.encode()
    }

    pub fn encode_quantity(&self) -> pallas::Base {
        pallas::Base::from(self.resource().quantity)
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    pub fn generate_input_token_resource_logics<R: RngCore>(
        &self,
        mut rng: R,
        auth: TokenAuthorization,
        auth_sk: pallas::Scalar,
        merkle_path: [(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH],
    ) -> ResourceLogics {
        // token resource logic
        let self_resource = ResourceExistenceWitness::new(self.resource, merkle_path);
        let token_resource_logic = TokenResourceLogicCircuit {
            self_resource,
            token_name: self.token_name.clone(),
            auth,
            receiver_resource_logic_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        };

        // token auth resource logic
        let token_auth_resource_logic = SignatureVerificationResourceLogicCircuit::from_sk_and_sign(
            &mut rng,
            self_resource,
            auth.vk,
            auth_sk,
            *COMPRESSED_RECEIVER_VK,
        );

        ResourceLogics::new(
            Box::new(token_resource_logic),
            vec![Box::new(token_auth_resource_logic)],
        )
    }

    pub fn generate_output_token_resource_logics<R: RngCore>(
        &self,
        mut rng: R,
        auth: TokenAuthorization,
        merkle_path: [(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH],
    ) -> ResourceLogics {
        let self_resource = ResourceExistenceWitness::new(self.resource, merkle_path);
        let token_resource_logic = TokenResourceLogicCircuit {
            self_resource,
            token_name: self.token_name.clone(),
            auth,
            receiver_resource_logic_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        };

        // receiver resource logic
        let receiver_resource_logic = ReceiverResourceLogicCircuit {
            self_resource,
            resource_logic_vk: *COMPRESSED_RECEIVER_VK,
            encrypt_nonce: pallas::Base::from_u128(rng.gen()),
            sk: pallas::Base::random(&mut rng),
            rcv_pk: auth.pk,
            auth_resource_logic_vk: *COMPRESSED_TOKEN_AUTH_VK,
        };

        ResourceLogics::new(
            Box::new(token_resource_logic),
            vec![Box::new(receiver_resource_logic)],
        )
    }
}

// TokenResourceLogicCircuit
#[derive(Clone, Debug)]
pub struct TokenResourceLogicCircuit {
    self_resource: ResourceExistenceWitness,
    // The token_name goes to label. It can be extended to a list and embedded to label.
    pub token_name: TokenName,
    // The auth goes to value and defines how to consume and create the resource.
    pub auth: TokenAuthorization,
    pub receiver_resource_logic_vk: pallas::Base,
    // rseed is to generate the randomness for resource_logic commitment
    pub rseed: RandomSeed,
}

#[derive(Clone, Debug, Copy)]
pub struct TokenAuthorization {
    pub pk: pallas::Point,
    pub vk: pallas::Base,
}

impl Default for TokenAuthorization {
    fn default() -> Self {
        Self {
            pk: pallas::Point::generator(),
            vk: pallas::Base::one(),
        }
    }
}

impl TokenResourceLogicCircuit {
    pub fn to_bytecode(&self) -> ResourceLogicByteCode {
        ResourceLogicByteCode::new(ResourceLogicRepresentation::Token, self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap()
    }
}

impl Default for TokenResourceLogicCircuit {
    fn default() -> Self {
        Self {
            self_resource: ResourceExistenceWitness::default(),
            token_name: TokenName("Token_name".to_string()),
            auth: TokenAuthorization::default(),
            receiver_resource_logic_vk: pallas::Base::zero(),
            rseed: RandomSeed::default(),
        }
    }
}

impl ResourceLogicCircuit for TokenResourceLogicCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        self_resource: ResourceStatus,
    ) -> Result<(), Error> {
        let token_property = assign_free_advice(
            layouter.namespace(|| "witness token_property"),
            config.advices[0],
            Value::known(self.token_name.encode()),
        )?;

        // We can add more constraints on token_property or extend the token_properties.

        // check label
        layouter.assign_region(
            || "check label",
            |mut region| {
                region.constrain_equal(token_property.cell(), self_resource.resource.label.cell())
            },
        )?;

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);

        let pk = NonIdentityPoint::new(
            ecc_chip,
            layouter.namespace(|| "witness pk"),
            Value::known(self.auth.pk.to_affine()),
        )?;

        let auth_resource_logic_vk = assign_free_advice(
            layouter.namespace(|| "witness auth resource_logic vk"),
            config.advices[0],
            Value::known(self.auth.vk),
        )?;

        let receiver_resource_logic_vk = assign_free_advice(
            layouter.namespace(|| "witness receiver resource_logic vk"),
            config.advices[0],
            Value::known(self.receiver_resource_logic_vk),
        )?;

        // Decode the value, and check the value encoding
        let encoded_value = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "value encoding"),
            [
                pk.inner().x(),
                pk.inner().y(),
                auth_resource_logic_vk.clone(),
                receiver_resource_logic_vk.clone(),
            ],
        )?;

        layouter.assign_region(
            || "check value encoding",
            |mut region| {
                region.constrain_equal(encoded_value.cell(), self_resource.resource.value.cell())
            },
        )?;

        // check the is_ephemeral flag
        let constant_zero = assign_free_constant(
            layouter.namespace(|| "zero"),
            config.advices[0],
            pallas::Base::zero(),
        )?;
        layouter.assign_region(
            || "check is_ephemeral",
            |mut region| {
                region.constrain_equal(
                    self_resource.resource.is_ephemeral.cell(),
                    constant_zero.cell(),
                )
            },
        )?;

        // Resource Logic Commitment
        // Commt the sender(authorization method included) resource_logic if it's an input resource;
        // Commit the receiver(resource encryption constraints included) resource_logic if it's an output resource.
        let first_dynamic_resource_logic = {
            layouter.assign_region(
                || "conditional select: ",
                |mut region| {
                    config.conditional_select_config.assign_region(
                        &self_resource.is_input,
                        &auth_resource_logic_vk,
                        &receiver_resource_logic_vk,
                        0,
                        &mut region,
                    )
                },
            )?
        };

        // Construct a blake2s chip
        let blake2s_chip = Blake2sChip::construct(config.blake2s_config);
        let resource_logic_cm_r = assign_free_advice(
            layouter.namespace(|| "resource_logic_cm_r"),
            config.advices[0],
            Value::known(
                self.rseed
                    .get_resource_logic_cm_r(PRF_EXPAND_DYNAMIC_RESOURCE_LOGIC_1_CM_R),
            ),
        )?;
        let first_dynamic_resource_logic_cm = resource_logic_commitment_gadget(
            &mut layouter,
            &blake2s_chip,
            first_dynamic_resource_logic,
            resource_logic_cm_r,
        )?;

        layouter.constrain_instance(
            first_dynamic_resource_logic_cm[0].cell(),
            config.instances,
            RESOURCE_LOGIC_CIRCUIT_FIRST_DYNAMIC_RESOURCE_LOGIC_CM_1,
        )?;
        layouter.constrain_instance(
            first_dynamic_resource_logic_cm[1].cell(),
            config.instances,
            RESOURCE_LOGIC_CIRCUIT_FIRST_DYNAMIC_RESOURCE_LOGIC_CM_2,
        )?;

        // Publicize the second dynamic resource_logic commitment with default value
        let resource_logic_cm_fields: [pallas::Base; 2] =
            ResourceLogicCommitment::default().to_public_inputs();
        let resource_logic_cm_1 = assign_free_advice(
            layouter.namespace(|| "resource_logic_cm 1"),
            config.advices[0],
            Value::known(resource_logic_cm_fields[0]),
        )?;
        let resource_logic_cm_2 = assign_free_advice(
            layouter.namespace(|| "resource_logic_cm 2"),
            config.advices[0],
            Value::known(resource_logic_cm_fields[1]),
        )?;

        layouter.constrain_instance(
            resource_logic_cm_1.cell(),
            config.instances,
            RESOURCE_LOGIC_CIRCUIT_SECOND_DYNAMIC_RESOURCE_LOGIC_CM_1,
        )?;
        layouter.constrain_instance(
            resource_logic_cm_2.cell(),
            config.instances,
            RESOURCE_LOGIC_CIRCUIT_SECOND_DYNAMIC_RESOURCE_LOGIC_CM_2,
        )?;

        Ok(())
    }

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ResourceLogicPublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let dynamic_resource_logic = if self.get_self_resource().is_input() {
            self.auth.vk
        } else {
            self.receiver_resource_logic_vk
        };

        let resource_logic_com_r = self
            .rseed
            .get_resource_logic_cm_r(PRF_EXPAND_DYNAMIC_RESOURCE_LOGIC_1_CM_R);
        let resource_logic_com: [pallas::Base; 2] =
            ResourceLogicCommitment::commit(&dynamic_resource_logic, &resource_logic_com_r)
                .to_public_inputs();

        public_inputs.extend(resource_logic_com);
        let default_resource_logic_cm: [pallas::Base; 2] =
            ResourceLogicCommitment::default().to_public_inputs();
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

resource_logic_circuit_impl!(TokenResourceLogicCircuit);
resource_logic_verifying_info_impl!(TokenResourceLogicCircuit);

impl BorshSerialize for TokenResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.self_resource.serialize(writer)?;
        self.token_name.serialize(writer)?;
        self.auth.serialize(writer)?;
        writer.write_all(&self.receiver_resource_logic_vk.to_repr())?;
        self.rseed.serialize(writer)?;

        Ok(())
    }
}

impl BorshDeserialize for TokenResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let self_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let token_name = TokenName::deserialize_reader(reader)?;
        let auth = TokenAuthorization::deserialize_reader(reader)?;
        let receiver_resource_logic_vk = read_base_field(reader)?;
        let rseed = RandomSeed::deserialize_reader(reader)?;
        Ok(Self {
            self_resource,
            token_name,
            auth,
            receiver_resource_logic_vk,
            rseed,
        })
    }
}

impl BorshSerialize for TokenAuthorization {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.pk.to_bytes())?;
        writer.write_all(&self.vk.to_repr())?;
        Ok(())
    }
}

impl BorshDeserialize for TokenAuthorization {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let pk = read_point(reader)?;
        let vk = read_base_field(reader)?;

        Ok(Self { pk, vk })
    }
}

impl TokenAuthorization {
    pub fn new(pk: pallas::Point, vk: pallas::Base) -> Self {
        Self { pk, vk }
    }

    pub fn random<R: RngCore>(mut rng: R) -> Self {
        Self {
            pk: pallas::Point::random(&mut rng),
            vk: *COMPRESSED_TOKEN_AUTH_VK,
        }
    }

    pub fn to_value(&self) -> pallas::Base {
        let pk_coord = self.pk.to_affine().coordinates().unwrap();
        poseidon_hash_n::<4>([
            *pk_coord.x(),
            *pk_coord.y(),
            self.vk,
            *COMPRESSED_RECEIVER_VK,
        ])
    }

    pub fn from_sk_vk(sk: &pallas::Scalar, vk: &pallas::Base) -> Self {
        let generator = pallas::Point::generator().to_affine();
        let pk = generator * sk;
        Self { pk, vk: *vk }
    }
}

#[test]
fn test_halo2_token_resource_logic_circuit() {
    use crate::constant::RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE;
    use crate::resource::tests::random_resource;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        // Create an input resource
        let mut resource = random_resource(&mut rng);
        let token_name = TokenName("Token_name".to_string());
        let auth = TokenAuthorization::random(&mut rng);
        resource.kind.label = token_name.encode();
        resource.value = auth.to_value();
        let merkle_path = [(pallas::Base::zero(), LR::R); TAIGA_RESOURCE_TREE_DEPTH];
        let self_resource = ResourceExistenceWitness::new(resource, merkle_path);
        TokenResourceLogicCircuit {
            self_resource,
            token_name,
            auth,
            receiver_resource_logic_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        }
    };

    // Test serialization
    let circuit = {
        let circuit_bytes = circuit.to_bytes();
        TokenResourceLogicCircuit::from_bytes(&circuit_bytes)
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
