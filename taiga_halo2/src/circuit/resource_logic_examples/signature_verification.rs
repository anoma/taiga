use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{
            assign_free_advice, poseidon_hash::poseidon_hash_gadget,
            target_resource_variable::get_owned_resource_variable,
        },
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            BasicResourceLogicVariables, ResourceLogicCircuit, ResourceLogicConfig,
            ResourceLogicPublicInputs, ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait,
        },
    },
    constant::{TaigaFixedBasesFull, NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    utils::{mod_r_p, poseidon_hash_n, read_base_field, read_point, read_scalar_field},
};
use borsh::{BorshDeserialize, BorshSerialize};
use halo2_gadgets::ecc::{chip::EccChip, FixedPoint, NonIdentityPoint, ScalarFixed, ScalarVar};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::{
    arithmetic::CurveAffine,
    group::{ff::PrimeField, Curve, Group, GroupEncoding},
    pallas,
};
use rand::rngs::OsRng;
use rand::RngCore;

// The message contains the input resource nullifiers and output resource commitments
const MESSAGE_LEN: usize = NUM_RESOURCE * 2;
const POSEIDON_HASH_LEN: usize = MESSAGE_LEN + 4;
lazy_static! {
    pub static ref TOKEN_AUTH_VK: ResourceLogicVerifyingKey =
        SignatureVerificationResourceLogicCircuit::default().get_resource_logic_vk();
    pub static ref COMPRESSED_TOKEN_AUTH_VK: pallas::Base = TOKEN_AUTH_VK.get_compressed();
}

#[derive(Clone, Debug)]
pub struct SchnorrSignature {
    // public key
    pk: pallas::Point,
    // signature (r,s)
    r: pallas::Point,
    s: pallas::Scalar,
}

impl Default for SchnorrSignature {
    fn default() -> Self {
        Self {
            pk: pallas::Point::generator(),
            r: pallas::Point::generator(),
            s: pallas::Scalar::one(),
        }
    }
}

impl SchnorrSignature {
    pub fn sign<R: RngCore>(mut rng: R, sk: pallas::Scalar, message: Vec<pallas::Base>) -> Self {
        // TDOD: figure out whether the generator is applicable.
        let generator = pallas::Point::generator();
        let pk = generator * sk;
        let pk_coord = pk.to_affine().coordinates().unwrap();
        // Generate a random number: z
        let z = pallas::Scalar::random(&mut rng);
        // Compute: R = z*G
        let r = generator * z;
        let r_coord = r.to_affine().coordinates().unwrap();
        // Compute: s = z + Hash(r||P||m)*sk
        assert_eq!(message.len(), MESSAGE_LEN);
        let h = mod_r_p(poseidon_hash_n::<POSEIDON_HASH_LEN>([
            *r_coord.x(),
            *r_coord.y(),
            *pk_coord.x(),
            *pk_coord.y(),
            message[0],
            message[1],
            message[2],
            message[3],
        ]));
        let s = z + h * sk;
        Self { pk, r, s }
    }
}

// SignatureVerificationResourceLogicCircuit uses the schnorr signature.
#[derive(Clone, Debug, Default)]
pub struct SignatureVerificationResourceLogicCircuit {
    pub self_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    pub resource_logic_vk: pallas::Base,
    pub signature: SchnorrSignature,
    pub receiver_resource_logic_vk: pallas::Base,
}

impl SignatureVerificationResourceLogicCircuit {
    pub fn new(
        self_resource_id: pallas::Base,
        input_resources: [Resource; NUM_RESOURCE],
        output_resources: [Resource; NUM_RESOURCE],
        resource_logic_vk: pallas::Base,
        signature: SchnorrSignature,
        receiver_resource_logic_vk: pallas::Base,
    ) -> Self {
        Self {
            self_resource_id,
            input_resources,
            output_resources,
            resource_logic_vk,
            signature,
            receiver_resource_logic_vk,
        }
    }

    pub fn from_sk_and_sign<R: RngCore>(
        mut rng: R,
        self_resource_id: pallas::Base,
        input_resources: [Resource; NUM_RESOURCE],
        output_resources: [Resource; NUM_RESOURCE],
        resource_logic_vk: pallas::Base,
        sk: pallas::Scalar,
        receiver_resource_logic_vk: pallas::Base,
    ) -> Self {
        assert_eq!(NUM_RESOURCE, 2);
        let mut message = vec![];
        input_resources
            .iter()
            .zip(output_resources.iter())
            .for_each(|(input_resource, output_resource)| {
                let nf = input_resource.get_nf().unwrap().inner();
                message.push(nf);
                let cm = output_resource.commitment();
                message.push(cm.inner());
            });
        let signature = SchnorrSignature::sign(&mut rng, sk, message);
        Self {
            self_resource_id,
            input_resources,
            output_resources,
            resource_logic_vk,
            signature,
            receiver_resource_logic_vk,
        }
    }

    pub fn to_bytecode(&self) -> ResourceLogicByteCode {
        ResourceLogicByteCode::new(
            ResourceLogicRepresentation::SignatureVerification,
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

impl ResourceLogicCircuit for SignatureVerificationResourceLogicCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicResourceLogicVariables,
    ) -> Result<(), Error> {
        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);

        let pk = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "witness pk"),
            Value::known(self.signature.pk.to_affine()),
        )?;

        // search target resource and get the value
        let self_resource_id = basic_variables.get_self_resource_id();
        let value = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource value"),
            &self_resource_id,
            &basic_variables.get_value_searchable_pairs(),
        )?;

        let auth_resource_logic_vk = assign_free_advice(
            layouter.namespace(|| "witness auth resource_logic vk"),
            config.advices[0],
            Value::known(self.resource_logic_vk),
        )?;
        let receiver_resource_logic_vk = assign_free_advice(
            layouter.namespace(|| "witness receiver resource_logic vk"),
            config.advices[0],
            Value::known(self.receiver_resource_logic_vk),
        )?;

        // Decode the value, and check the value encoding
        let encoded_value = poseidon_hash_gadget(
            config.poseidon_config.clone(),
            layouter.namespace(|| "value encoding"),
            [
                pk.inner().x(),
                pk.inner().y(),
                auth_resource_logic_vk,
                receiver_resource_logic_vk,
            ],
        )?;

        layouter.assign_region(
            || "check value encoding",
            |mut region| region.constrain_equal(encoded_value.cell(), value.cell()),
        )?;

        let r = NonIdentityPoint::new(
            ecc_chip.clone(),
            layouter.namespace(|| "witness r"),
            Value::known(self.signature.r.to_affine()),
        )?;
        let s_scalar = ScalarFixed::new(
            ecc_chip.clone(),
            layouter.namespace(|| "witness s"),
            Value::known(self.signature.s),
        )?;

        // Verify: s*G = R + Hash(r||P||m)*P
        // s*G
        let generator =
            FixedPoint::from_inner(ecc_chip.clone(), TaigaFixedBasesFull::BaseGenerator);
        let (s_g, _) = generator.mul(layouter.namespace(|| "s_scalar * generator"), &s_scalar)?;

        // Hash(r||P||m)
        let h_scalar = {
            let nfs = basic_variables.get_input_resource_nfs();
            let cms = basic_variables.get_output_resource_cms();
            assert_eq!(NUM_RESOURCE, 2);
            let h = poseidon_hash_gadget(
                config.poseidon_config,
                layouter.namespace(|| "Poseidon_hash(r, P, m)"),
                [
                    r.inner().x(),
                    r.inner().y(),
                    pk.inner().x(),
                    pk.inner().y(),
                    nfs[0].clone(),
                    cms[0].clone(),
                    nfs[1].clone(),
                    cms[1].clone(),
                ],
            )?;

            ScalarVar::from_base(ecc_chip, layouter.namespace(|| "ScalarVar from_base"), &h)?
        };

        // Hash(r||P||m)*P
        let (h_p, _) = pk.mul(layouter.namespace(|| "hP"), h_scalar)?;

        // R + Hash(r||P||m)*P
        let rhs = r.add(layouter.namespace(|| "R + Hash(r||P||m)*P"), &h_p)?;

        s_g.constrain_equal(layouter.namespace(|| "s*G = R + Hash(r||P||m)*P"), &rhs)?;

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

resource_logic_circuit_impl!(SignatureVerificationResourceLogicCircuit);
resource_logic_verifying_info_impl!(SignatureVerificationResourceLogicCircuit);

impl BorshSerialize for SignatureVerificationResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.self_resource_id.to_repr())?;
        for input in self.input_resources.iter() {
            input.serialize(writer)?;
        }

        for output in self.output_resources.iter() {
            output.serialize(writer)?;
        }

        writer.write_all(&self.resource_logic_vk.to_repr())?;
        self.signature.serialize(writer)?;
        writer.write_all(&self.receiver_resource_logic_vk.to_repr())?;

        Ok(())
    }
}

impl BorshDeserialize for SignatureVerificationResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let self_resource_id = read_base_field(reader)?;
        let input_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let output_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let resource_logic_vk = read_base_field(reader)?;
        let signature = SchnorrSignature::deserialize_reader(reader)?;
        let receiver_resource_logic_vk = read_base_field(reader)?;
        Ok(Self {
            self_resource_id,
            input_resources: input_resources.try_into().unwrap(),
            output_resources: output_resources.try_into().unwrap(),
            resource_logic_vk,
            signature,
            receiver_resource_logic_vk,
        })
    }
}

impl BorshSerialize for SchnorrSignature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.pk.to_bytes())?;
        writer.write_all(&self.r.to_bytes())?;
        writer.write_all(&self.s.to_repr())?;

        Ok(())
    }
}

impl BorshDeserialize for SchnorrSignature {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let pk = read_point(reader)?;
        let r = read_point(reader)?;
        let s = read_scalar_field(reader)?;
        Ok(Self { pk, r, s })
    }
}

#[test]
fn test_halo2_sig_verification_resource_logic_circuit() {
    use crate::circuit::resource_logic_examples::{
        receiver_resource_logic::COMPRESSED_RECEIVER_VK, token::TokenAuthorization,
    };
    use crate::constant::RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE;
    use crate::resource::tests::random_resource;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let mut input_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let sk = pallas::Scalar::random(&mut rng);
        let auth_vk = pallas::Base::random(&mut rng);
        let auth = TokenAuthorization::from_sk_vk(&sk, &auth_vk);
        input_resources[0].value = auth.to_value();
        let self_resource_id = input_resources[0].get_nf().unwrap().inner();
        SignatureVerificationResourceLogicCircuit::from_sk_and_sign(
            &mut rng,
            self_resource_id,
            input_resources,
            output_resources,
            auth_vk,
            sk,
            *COMPRESSED_RECEIVER_VK,
        )
    };

    // Test serialization
    let circuit = {
        let circuit_bytes = circuit.to_bytes();
        SignatureVerificationResourceLogicCircuit::from_bytes(&circuit_bytes)
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
