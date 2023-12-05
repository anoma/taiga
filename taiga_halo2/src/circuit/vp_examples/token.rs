use crate::circuit::vp_bytecode::{ValidityPredicateByteCode, ValidityPredicateRepresentation};
use crate::{
    circuit::{
        blake2s::{vp_commitment_gadget, Blake2sChip},
        gadgets::{
            assign_free_advice, assign_free_constant,
            poseidon_hash::poseidon_hash_gadget,
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
        vp_examples::receiver_vp::{ReceiverValidityPredicateCircuit, COMPRESSED_RECEIVER_VK},
        vp_examples::signature_verification::{
            SignatureVerificationValidityPredicateCircuit, COMPRESSED_TOKEN_AUTH_VK,
        },
    },
    constant::{
        NUM_RESOURCE, PRF_EXPAND_DYNAMIC_VP_1_CM_R, SETUP_PARAMS_MAP,
        VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_1, VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_2,
        VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_1, VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_2,
    },
    error::TransactionError,
    nullifier::Nullifier,
    proof::Proof,
    resource::{RandomSeed, Resource, ResourceValidityPredicates},
    utils::poseidon_hash_n,
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
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
    pub static ref TOKEN_VK: ValidityPredicateVerifyingKey =
        TokenValidityPredicateCircuit::default().get_vp_vk();
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

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug, Default)]
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

    pub fn generate_input_token_vps<R: RngCore>(
        &self,
        mut rng: R,
        auth: TokenAuthorization,
        auth_sk: pallas::Scalar,
        input_resources: [Resource; NUM_RESOURCE],
        output_resources: [Resource; NUM_RESOURCE],
    ) -> ResourceValidityPredicates {
        let TokenResource {
            token_name,
            resource,
        } = self;
        // token VP
        let nf = resource.get_nf().unwrap().inner();
        let token_vp = TokenValidityPredicateCircuit {
            owned_resource_id: nf,
            input_resources,
            output_resources,
            token_name: token_name.clone(),
            auth,
            receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        };

        // token auth VP
        let token_auth_vp = SignatureVerificationValidityPredicateCircuit::from_sk_and_sign(
            &mut rng,
            nf,
            input_resources,
            output_resources,
            auth.vk,
            auth_sk,
            *COMPRESSED_RECEIVER_VK,
        );

        ResourceValidityPredicates::new(Box::new(token_vp), vec![Box::new(token_auth_vp)])
    }

    pub fn generate_output_token_vps<R: RngCore>(
        &self,
        mut rng: R,
        auth: TokenAuthorization,
        input_resources: [Resource; NUM_RESOURCE],
        output_resources: [Resource; NUM_RESOURCE],
    ) -> ResourceValidityPredicates {
        let TokenResource {
            token_name,
            resource,
        } = self;

        let owned_resource_id = resource.commitment().inner();
        // token VP
        let token_vp = TokenValidityPredicateCircuit {
            owned_resource_id,
            input_resources,
            output_resources,
            token_name: token_name.clone(),
            auth,
            receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        };

        // receiver VP
        let receiver_vp = ReceiverValidityPredicateCircuit {
            owned_resource_id,
            input_resources,
            output_resources,
            vp_vk: *COMPRESSED_RECEIVER_VK,
            encrypt_nonce: pallas::Base::from_u128(rng.gen()),
            sk: pallas::Base::random(&mut rng),
            rcv_pk: auth.pk,
            auth_vp_vk: *COMPRESSED_TOKEN_AUTH_VK,
        };

        ResourceValidityPredicates::new(Box::new(token_vp), vec![Box::new(receiver_vp)])
    }
}

// TokenValidityPredicateCircuit
#[derive(Clone, Debug)]
pub struct TokenValidityPredicateCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    // The token_name goes to label. It can be extended to a list and embedded to label.
    pub token_name: TokenName,
    // The auth goes to value and defines how to consume and create the resource.
    pub auth: TokenAuthorization,
    pub receiver_vp_vk: pallas::Base,
    // rseed is to generate the randomness for vp commitment
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

impl TokenValidityPredicateCircuit {
    pub fn to_bytecode(&self) -> ValidityPredicateByteCode {
        ValidityPredicateByteCode::new(ValidityPredicateRepresentation::Token, self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap()
    }
}

impl Default for TokenValidityPredicateCircuit {
    fn default() -> Self {
        Self {
            owned_resource_id: pallas::Base::zero(),
            input_resources: [(); NUM_RESOURCE].map(|_| Resource::default()),
            output_resources: [(); NUM_RESOURCE].map(|_| Resource::default()),
            token_name: TokenName("Token_name".to_string()),
            auth: TokenAuthorization::default(),
            receiver_vp_vk: pallas::Base::zero(),
            rseed: RandomSeed::default(),
        }
    }
}

impl ValidityPredicateCircuit for TokenValidityPredicateCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        let owned_resource_id = basic_variables.get_owned_resource_id();

        let token_property = assign_free_advice(
            layouter.namespace(|| "witness token_property"),
            config.advices[0],
            Value::known(self.token_name.encode()),
        )?;

        // We can add more constraints on token_property or extend the token_properties.

        // search target resource and get the label
        let label = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource label"),
            &owned_resource_id,
            &basic_variables.get_label_searchable_pairs(),
        )?;

        // check label
        layouter.assign_region(
            || "check label",
            |mut region| region.constrain_equal(token_property.cell(), label.cell()),
        )?;

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);

        let pk = NonIdentityPoint::new(
            ecc_chip,
            layouter.namespace(|| "witness pk"),
            Value::known(self.auth.pk.to_affine()),
        )?;

        let auth_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness auth vp vk"),
            config.advices[0],
            Value::known(self.auth.vk),
        )?;

        // search target resource and get the value
        let value = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource value"),
            &owned_resource_id,
            &basic_variables.get_value_searchable_pairs(),
        )?;

        let receiver_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness receiver vp vk"),
            config.advices[0],
            Value::known(self.receiver_vp_vk),
        )?;

        // Decode the value, and check the value encoding
        let encoded_value = poseidon_hash_gadget(
            config.poseidon_config,
            layouter.namespace(|| "value encoding"),
            [
                pk.inner().x(),
                pk.inner().y(),
                auth_vp_vk.clone(),
                receiver_vp_vk.clone(),
            ],
        )?;

        layouter.assign_region(
            || "check value encoding",
            |mut region| region.constrain_equal(encoded_value.cell(), value.cell()),
        )?;

        // check the is_ephemeral flag
        let is_ephemeral = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get is_ephemeral"),
            &owned_resource_id,
            &basic_variables.get_is_ephemeral_searchable_pairs(),
        )?;
        let constant_zero = assign_free_constant(
            layouter.namespace(|| "zero"),
            config.advices[0],
            pallas::Base::zero(),
        )?;
        layouter.assign_region(
            || "check is_ephemeral",
            |mut region| region.constrain_equal(is_ephemeral.cell(), constant_zero.cell()),
        )?;

        // VP Commitment
        // Commt the sender(authorization method included) vp if it's an input resource;
        // Commit the receiver(resource encryption constraints included) vp if it's an output resource.
        let first_dynamic_vp = {
            let is_input_resource = get_is_input_resource_flag(
                config.get_is_input_resource_flag_config,
                layouter.namespace(|| "get is_input_resource_flag"),
                &owned_resource_id,
                &basic_variables.get_input_resource_nfs(),
                &basic_variables.get_output_resource_cms(),
            )?;
            layouter.assign_region(
                || "conditional select: ",
                |mut region| {
                    config.conditional_select_config.assign_region(
                        &is_input_resource,
                        &auth_vp_vk,
                        &receiver_vp_vk,
                        0,
                        &mut region,
                    )
                },
            )?
        };

        // Construct a blake2s chip
        let blake2s_chip = Blake2sChip::construct(config.blake2s_config);
        let vp_cm_r = assign_free_advice(
            layouter.namespace(|| "vp_cm_r"),
            config.advices[0],
            Value::known(self.rseed.get_vp_cm_r(PRF_EXPAND_DYNAMIC_VP_1_CM_R)),
        )?;
        let first_dynamic_vp_cm =
            vp_commitment_gadget(&mut layouter, &blake2s_chip, first_dynamic_vp, vp_cm_r)?;

        layouter.constrain_instance(
            first_dynamic_vp_cm[0].cell(),
            config.instances,
            VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_1,
        )?;
        layouter.constrain_instance(
            first_dynamic_vp_cm[1].cell(),
            config.instances,
            VP_CIRCUIT_FIRST_DYNAMIC_VP_CM_2,
        )?;

        // Publicize the second dynamic vp commitment with default value
        let vp_cm_fields: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
        let vp_cm_1 = assign_free_advice(
            layouter.namespace(|| "vp_cm 1"),
            config.advices[0],
            Value::known(vp_cm_fields[0]),
        )?;
        let vp_cm_2 = assign_free_advice(
            layouter.namespace(|| "vp_cm 2"),
            config.advices[0],
            Value::known(vp_cm_fields[1]),
        )?;

        layouter.constrain_instance(
            vp_cm_1.cell(),
            config.instances,
            VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_1,
        )?;
        layouter.constrain_instance(
            vp_cm_2.cell(),
            config.instances,
            VP_CIRCUIT_SECOND_DYNAMIC_VP_CM_2,
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
        let dynamic_vp = if self.owned_resource_id == self.output_resources[0].commitment().inner()
            || self.owned_resource_id == self.output_resources[1].commitment().inner()
        {
            self.receiver_vp_vk
        } else {
            self.auth.vk
        };

        let vp_com_r = self.rseed.get_vp_cm_r(PRF_EXPAND_DYNAMIC_VP_1_CM_R);
        let vp_com: [pallas::Base; 2] =
            ValidityPredicateCommitment::commit(&dynamic_vp, &vp_com_r).to_public_inputs();

        public_inputs.extend(vp_com);
        let default_vp_cm: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
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

vp_circuit_impl!(TokenValidityPredicateCircuit);
vp_verifying_info_impl!(TokenValidityPredicateCircuit);

impl BorshSerialize for TokenValidityPredicateCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.owned_resource_id.to_repr())?;
        for input in self.input_resources.iter() {
            input.serialize(writer)?;
        }

        for output in self.output_resources.iter() {
            output.serialize(writer)?;
        }

        self.token_name.serialize(writer)?;

        writer.write_all(&self.auth.pk.to_bytes())?;
        writer.write_all(&self.auth.vk.to_repr())?;
        writer.write_all(&self.receiver_vp_vk.to_repr())?;
        self.rseed.serialize(writer)?;

        Ok(())
    }
}

impl BorshDeserialize for TokenValidityPredicateCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let owned_resource_id_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let owned_resource_id = Option::from(pallas::Base::from_repr(owned_resource_id_bytes))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "owned_resource_id not in field",
                )
            })?;
        let input_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let output_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let token_name = TokenName::deserialize_reader(reader)?;
        let pk_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let pk = Option::from(pallas::Point::from_bytes(&pk_bytes)).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "owned_resource_id not in point",
            )
        })?;
        let vk_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let vk = Option::from(pallas::Base::from_repr(vk_bytes)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "vk not in field")
        })?;
        let auth = TokenAuthorization { pk, vk };
        let receiver_vp_vk_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let receiver_vp_vk = Option::from(pallas::Base::from_repr(receiver_vp_vk_bytes))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "receiver_vp_vk not in field",
                )
            })?;
        let rseed = RandomSeed::deserialize_reader(reader)?;
        Ok(Self {
            owned_resource_id,
            input_resources: input_resources.try_into().unwrap(),
            output_resources: output_resources.try_into().unwrap(),
            token_name,
            auth,
            receiver_vp_vk,
            rseed,
        })
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
fn test_halo2_token_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
    use crate::resource::tests::random_resource;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let mut input_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let token_name = TokenName("Token_name".to_string());
        let auth = TokenAuthorization::random(&mut rng);
        input_resources[0].kind.label = token_name.encode();
        input_resources[0].value = auth.to_value();
        TokenValidityPredicateCircuit {
            owned_resource_id: input_resources[0].get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            token_name,
            auth,
            receiver_vp_vk: *COMPRESSED_RECEIVER_VK,
            rseed: RandomSeed::random(&mut rng),
        }
    };

    // Test serialization
    let circuit = {
        let circuit_bytes = circuit.to_bytes();
        TokenValidityPredicateCircuit::from_bytes(&circuit_bytes)
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
