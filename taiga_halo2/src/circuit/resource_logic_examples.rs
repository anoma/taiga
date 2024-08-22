#[cfg(feature = "borsh")]
use crate::circuit::resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation};
use crate::{
    circuit::resource_logic_circuit::{
        ResourceLogicCircuit, ResourceLogicConfig, ResourceLogicPublicInputs,
        ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait,
    },
    constant::{RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE, SETUP_PARAMS_MAP},
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    resource_tree::ResourceExistenceWitness,
};
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::{pallas, vesta};
use rand::{rngs::OsRng, RngCore};
#[cfg(feature = "nif")]
use rustler::{Decoder, Encoder, Env, NifResult, NifStruct, Term};

#[cfg(feature = "examples")]
pub mod cascade_intent;
#[cfg(feature = "examples")]
mod field_addition;
#[cfg(feature = "examples")]
pub mod or_relation_intent;
#[cfg(feature = "examples")]
pub mod partial_fulfillment_intent;
#[cfg(feature = "examples")]
pub mod receiver_resource_logic;
#[cfg(feature = "examples")]
pub mod signature_verification;
#[cfg(feature = "examples")]
pub mod token;

lazy_static! {
    pub static ref TRIVIAL_RESOURCE_LOGIC_VK: ResourceLogicVerifyingKey = {
        let params = SETUP_PARAMS_MAP
            .get(&RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE)
            .unwrap();
        let empty_circuit = TrivialResourceLogicCircuit::default();
        let vk = keygen_vk(params, &empty_circuit).expect("keygen_vk should not fail");
        ResourceLogicVerifyingKey::from_vk(vk)
    };
    pub static ref TRIVIAL_RESOURCE_LOGIC_PK: ProvingKey<vesta::Affine> = {
        let params = SETUP_PARAMS_MAP
            .get(&RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE)
            .unwrap();
        let empty_circuit = TrivialResourceLogicCircuit::default();
        keygen_pk(
            params,
            TRIVIAL_RESOURCE_LOGIC_VK.get_vk().unwrap(),
            &empty_circuit,
        )
        .expect("keygen_pk should not fail")
    };
    pub static ref COMPRESSED_TRIVIAL_RESOURCE_LOGIC_VK: pallas::Base =
        TRIVIAL_RESOURCE_LOGIC_VK.get_compressed();
}

// TrivialResourceLogicCircuit with empty custom constraints.
#[derive(Clone, Debug, Default)]
pub struct TrivialResourceLogicCircuit {
    self_resource: ResourceExistenceWitness,
}

impl TrivialResourceLogicCircuit {
    pub fn new(self_resource: ResourceExistenceWitness) -> Self {
        Self { self_resource }
    }

    // Only for test
    #[cfg(feature = "borsh")]
    pub fn to_bytecode(&self) -> ResourceLogicByteCode {
        ResourceLogicByteCode::new(ResourceLogicRepresentation::Trivial, self.to_bytes())
    }

    // Only for test
    #[cfg(feature = "borsh")]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    // Only for test
    #[cfg(feature = "borsh")]
    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap()
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for TrivialResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use ff::PrimeField;
        writer.write_all(&self.owned_resource_id.to_repr())?;
        for input in self.input_resources.iter() {
            input.serialize(writer)?;
        }

        for output in self.output_resources.iter() {
            output.serialize(writer)?;
        }
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for TrivialResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let owned_resource_id = crate::utils::read_base_field(reader)?;
        let input_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let output_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            owned_resource_id,
            input_resources: input_resources.try_into().unwrap(),
            output_resources: output_resources.try_into().unwrap(),
        })
    }
}

impl ResourceLogicCircuit for TrivialResourceLogicCircuit {
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

resource_logic_circuit_impl!(TrivialResourceLogicCircuit);

impl ResourceLogicVerifyingInfoTrait for TrivialResourceLogicCircuit {
    fn get_verifying_info(&self) -> ResourceLogicVerifyingInfo {
        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&15).unwrap();
        let public_inputs = self.get_public_inputs(&mut rng);
        let proof = Proof::create(
            &TRIVIAL_RESOURCE_LOGIC_PK,
            params,
            self.clone(),
            &[public_inputs.inner()],
            &mut rng,
        )
        .unwrap();
        ResourceLogicVerifyingInfo {
            vk: TRIVIAL_RESOURCE_LOGIC_PK.get_vk().clone(),
            proof,
            public_inputs,
        }
    }

    fn verify_transparently(&self) -> Result<ResourceLogicPublicInputs, TransactionError> {
        use halo2_proofs::dev::MockProver;
        let mut rng = OsRng;
        let public_inputs = self.get_public_inputs(&mut rng);
        let prover =
            MockProver::<pallas::Base>::run(15, self, vec![public_inputs.to_vec()]).unwrap();
        prover.verify().unwrap();
        Ok(public_inputs)
    }

    fn get_resource_logic_vk(&self) -> ResourceLogicVerifyingKey {
        TRIVIAL_RESOURCE_LOGIC_VK.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::TrivialResourceLogicCircuit;
    use pasta_curves::pallas;

    #[test]
    fn test_halo2_trivial_resource_logic_circuit() {
        use crate::circuit::resource_logic_circuit::ResourceLogicCircuit;
        use crate::constant::RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE;
        use halo2_proofs::dev::MockProver;
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let circuit = TrivialResourceLogicCircuit::default();
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
