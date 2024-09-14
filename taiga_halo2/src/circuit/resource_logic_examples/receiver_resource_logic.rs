use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{add::AddChip, assign_free_advice, poseidon_hash::poseidon_hash_gadget},
        resource_encryption_circuit::resource_encryption_gadget,
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            ResourceLogicCircuit, ResourceLogicConfig, ResourceLogicPublicInputs,
            ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait, ResourceStatus,
        },
        resource_logic_examples::signature_verification::COMPRESSED_TOKEN_AUTH_VK,
    },
    constant::{GENERATOR, SETUP_PARAMS_MAP},
    error::TransactionError,
    proof::Proof,
    resource::RandomSeed,
    resource_encryption::{ResourceCiphertext, ResourcePlaintext, SecretKey},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    resource_tree::ResourceExistenceWitness,
    utils::{mod_r_p, read_base_field, read_point},
};
use borsh::{BorshDeserialize, BorshSerialize};
use group::{cofactor::CofactorCurveAffine, ff::PrimeField, Curve, Group, GroupEncoding};
use halo2_gadgets::ecc::{chip::EccChip, NonIdentityPoint};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

const CIPHER_LEN: usize = 9;

lazy_static! {
    pub static ref RECEIVER_VK: ResourceLogicVerifyingKey =
        ReceiverResourceLogicCircuit::default().get_resource_logic_vk();
    pub static ref COMPRESSED_RECEIVER_VK: pallas::Base = RECEIVER_VK.get_compressed();
}

// ReceiverResourceLogicCircuit is used in the token resource_logic as dynamic resource_logic and contains the resource encryption constraints.
#[derive(Clone, Debug)]
pub struct ReceiverResourceLogicCircuit {
    pub self_resource: ResourceExistenceWitness,
    pub resource_logic_vk: pallas::Base,
    pub encrypt_nonce: pallas::Base,
    pub sk: pallas::Base,
    pub rcv_pk: pallas::Point,
    pub auth_resource_logic_vk: pallas::Base,
}

impl ReceiverResourceLogicCircuit {
    pub fn to_bytecode(&self) -> ResourceLogicByteCode {
        ResourceLogicByteCode::new(ResourceLogicRepresentation::Receiver, self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap()
    }
}

impl Default for ReceiverResourceLogicCircuit {
    fn default() -> Self {
        Self {
            self_resource: ResourceExistenceWitness::default(),
            resource_logic_vk: pallas::Base::zero(),
            encrypt_nonce: pallas::Base::zero(),
            sk: pallas::Base::zero(),
            rcv_pk: pallas::Point::generator(),
            auth_resource_logic_vk: pallas::Base::zero(),
        }
    }
}

impl ResourceLogicCircuit for ReceiverResourceLogicCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        self_resource: ResourceStatus,
    ) -> Result<(), Error> {
        let encrypt_nonce = assign_free_advice(
            layouter.namespace(|| "witness encrypt_nonce"),
            config.advices[0],
            Value::known(self.encrypt_nonce),
        )?;

        let sk = assign_free_advice(
            layouter.namespace(|| "witness sk"),
            config.advices[0],
            Value::known(self.sk),
        )?;

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);

        let rcv_pk = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "witness rcv_pk"),
            Value::known(self.rcv_pk.to_affine()),
        )?;

        let auth_resource_logic_vk = assign_free_advice(
            layouter.namespace(|| "witness auth resource_logic vk"),
            config.advices[0],
            Value::known(*COMPRESSED_TOKEN_AUTH_VK),
        )?;
        let receiver_resource_logic_vk = assign_free_advice(
            layouter.namespace(|| "witness receiver resource_logic vk"),
            config.advices[0],
            Value::known(self.resource_logic_vk),
        )?;

        // Decode the value, and check the value encoding
        let encoded_value = poseidon_hash_gadget(
            config.poseidon_config.clone(),
            layouter.namespace(|| "value encoding"),
            [
                rcv_pk.inner().x(),
                rcv_pk.inner().y(),
                auth_resource_logic_vk,
                receiver_resource_logic_vk,
            ],
        )?;

        layouter.assign_region(
            || "check value encoding",
            |mut region| {
                region.constrain_equal(encoded_value.cell(), self_resource.resource.value.cell())
            },
        )?;

        let mut message = vec![
            self_resource.resource.logic,
            self_resource.resource.label,
            self_resource.resource.value,
            self_resource.resource.quantity,
            self_resource.resource.nonce,
            self_resource.resource.npk,
            self_resource.resource.is_ephemeral,
            self_resource.resource.rseed,
        ];

        let add_chip = AddChip::<pallas::Base>::construct(config.add_config.clone(), ());

        // Encryption
        resource_encryption_gadget(
            layouter.namespace(|| "resource encryption"),
            config.advices[0],
            config.instances,
            config.poseidon_config,
            add_chip,
            ecc_chip,
            encrypt_nonce,
            sk,
            rcv_pk,
            &mut message,
        )?;

        // Publicize the dynamic resource_logic commitments with default value
        publicize_default_dynamic_resource_logic_commitments(
            &mut layouter,
            config.advices[0],
            config.instances,
        )?;

        Ok(())
    }

    fn get_public_inputs(&self, rng: impl RngCore) -> ResourceLogicPublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let default_resource_logic_cm: [pallas::Base; 2] =
            ResourceLogicCommitment::default().to_public_inputs();
        public_inputs.extend(default_resource_logic_cm);
        public_inputs.extend(default_resource_logic_cm);
        let custom_public_input_padding =
            ResourceLogicPublicInputs::get_custom_public_input_padding(
                public_inputs.len(),
                &RandomSeed::random(rng),
            );
        public_inputs.extend(custom_public_input_padding.iter());

        let self_resource = self.self_resource.get_resource();
        let message = vec![
            self_resource.kind.logic,
            self_resource.kind.label,
            self_resource.value,
            pallas::Base::from(self_resource.quantity),
            self_resource.nonce.inner(),
            self_resource.get_npk(),
            pallas::Base::from(self_resource.is_ephemeral as u64),
            self_resource.rseed,
        ];
        let plaintext = ResourcePlaintext::padding(&message);
        let key = SecretKey::from_dh_exchange(&self.rcv_pk, &mod_r_p(self.sk));
        let cipher = ResourceCiphertext::encrypt(&plaintext, &key, &self.encrypt_nonce);
        cipher.inner().iter().for_each(|&c| public_inputs.push(c));

        let generator = GENERATOR.to_curve();
        let pk = generator * mod_r_p(self.sk);
        let pk_coord = pk.to_affine().coordinates().unwrap();
        public_inputs.push(*pk_coord.x());
        public_inputs.push(*pk_coord.y());
        public_inputs.into()
    }

    fn get_self_resource(&self) -> ResourceExistenceWitness {
        self.self_resource
    }
}

resource_logic_circuit_impl!(ReceiverResourceLogicCircuit);
resource_logic_verifying_info_impl!(ReceiverResourceLogicCircuit);

impl BorshSerialize for ReceiverResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.self_resource.serialize(writer)?;
        writer.write_all(&self.resource_logic_vk.to_repr())?;
        writer.write_all(&self.encrypt_nonce.to_repr())?;
        writer.write_all(&self.sk.to_repr())?;
        writer.write_all(&self.rcv_pk.to_bytes())?;
        writer.write_all(&self.auth_resource_logic_vk.to_repr())?;

        Ok(())
    }
}

impl BorshDeserialize for ReceiverResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let self_resource = ResourceExistenceWitness::deserialize_reader(reader)?;
        let resource_logic_vk = read_base_field(reader)?;
        let encrypt_nonce = read_base_field(reader)?;
        let sk = read_base_field(reader)?;
        let rcv_pk = read_point(reader)?;
        let auth_resource_logic_vk = read_base_field(reader)?;
        Ok(Self {
            self_resource,
            resource_logic_vk,
            encrypt_nonce,
            sk,
            rcv_pk,
            auth_resource_logic_vk,
        })
    }
}

#[test]
fn test_halo2_receiver_resource_logic_circuit() {
    use crate::constant::{RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE, TAIGA_RESOURCE_TREE_DEPTH};
    use crate::merkle_tree::LR;
    use crate::{resource::tests::random_resource, utils::poseidon_hash_n};
    use ff::{Field, PrimeField};
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (circuit, rcv_sk) = {
        // Create an output resource
        let mut resource = random_resource(&mut rng);
        let encrypt_nonce = pallas::Base::from_u128(23333u128);
        let sk = pallas::Base::random(&mut rng);
        let rcv_sk = pallas::Base::random(&mut rng);
        let generator = GENERATOR.to_curve();
        let rcv_pk = generator * mod_r_p(rcv_sk);
        let rcv_pk_coord = rcv_pk.to_affine().coordinates().unwrap();
        resource.value = poseidon_hash_n([
            *rcv_pk_coord.x(),
            *rcv_pk_coord.y(),
            *COMPRESSED_TOKEN_AUTH_VK,
            *COMPRESSED_RECEIVER_VK,
        ]);
        let merkle_path = [(pallas::Base::zero(), LR::L); TAIGA_RESOURCE_TREE_DEPTH];
        let self_resource = ResourceExistenceWitness::new(resource, merkle_path);
        (
            ReceiverResourceLogicCircuit {
                self_resource,
                resource_logic_vk: *COMPRESSED_RECEIVER_VK,
                encrypt_nonce,
                sk,
                rcv_pk,
                auth_resource_logic_vk: *COMPRESSED_TOKEN_AUTH_VK,
            },
            rcv_sk,
        )
    };

    // Test serialization
    let circuit = {
        let circuit_bytes = circuit.to_bytes();
        ReceiverResourceLogicCircuit::from_bytes(&circuit_bytes)
    };

    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover = MockProver::<pallas::Base>::run(
        RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
        &circuit,
        vec![public_inputs.to_vec()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let de_cipher = public_inputs.decrypt(rcv_sk).unwrap();
    let original_resource = circuit.self_resource.get_resource();
    assert_eq!(de_cipher[0], original_resource.get_logic());
    assert_eq!(de_cipher[1], original_resource.get_label());
    assert_eq!(de_cipher[2], original_resource.value);
    assert_eq!(de_cipher[3], pallas::Base::from(original_resource.quantity));
    assert_eq!(de_cipher[4], original_resource.nonce.inner());
    assert_eq!(de_cipher[5], original_resource.get_npk());
    assert_eq!(
        de_cipher[6],
        pallas::Base::from(original_resource.is_ephemeral)
    );
    assert_eq!(de_cipher[7], original_resource.rseed);
}
