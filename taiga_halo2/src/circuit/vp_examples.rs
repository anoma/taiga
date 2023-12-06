#[cfg(feature = "borsh")]
use crate::circuit::vp_bytecode::{ValidityPredicateByteCode, ValidityPredicateRepresentation};
use crate::{
    circuit::vp_circuit::{
        VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
        ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP, VP_CIRCUIT_PARAMS_SIZE},
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    utils::read_base_field,
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
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
pub mod receiver_vp;
#[cfg(feature = "examples")]
pub mod signature_verification;
#[cfg(feature = "examples")]
pub mod token;

lazy_static! {
    pub static ref TRIVIAL_VP_VK: ValidityPredicateVerifyingKey = {
        let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        let empty_circuit = TrivialValidityPredicateCircuit::default();
        let vk = keygen_vk(params, &empty_circuit).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
    };
    pub static ref TRIVIAL_VP_PK: ProvingKey<vesta::Affine> = {
        let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        let empty_circuit = TrivialValidityPredicateCircuit::default();
        keygen_pk(params, TRIVIAL_VP_VK.get_vk().unwrap(), &empty_circuit)
            .expect("keygen_pk should not fail")
    };
    pub static ref COMPRESSED_TRIVIAL_VP_VK: pallas::Base = TRIVIAL_VP_VK.get_compressed();
}

// TrivialValidityPredicateCircuit with empty custom constraints.
#[derive(Clone, Debug, Default)]
pub struct TrivialValidityPredicateCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
}

// I only exist to allow trivial derivation of the nifstruct
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.VP.Trivial")]
struct TrivialValidtyPredicateCircuitProxy {
    owned_resource_id: pallas::Base,
    input_resources: Vec<Resource>,
    output_resources: Vec<Resource>,
}

impl TrivialValidityPredicateCircuit {
    pub fn new(
        owned_resource_id: pallas::Base,
        input_resources: [Resource; NUM_RESOURCE],
        output_resources: [Resource; NUM_RESOURCE],
    ) -> Self {
        Self {
            owned_resource_id,
            input_resources,
            output_resources,
        }
    }

    // Only for test
    #[cfg(feature = "borsh")]
    pub fn to_bytecode(&self) -> ValidityPredicateByteCode {
        ValidityPredicateByteCode::new(ValidityPredicateRepresentation::Trivial, self.to_bytes())
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

    fn to_proxy(&self) -> TrivialValidtyPredicateCircuitProxy {
        TrivialValidtyPredicateCircuitProxy {
            owned_resource_id: self.owned_resource_id,
            input_resources: self.input_resources.to_vec(),
            output_resources: self.output_resources.to_vec(),
        }
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for TrivialValidityPredicateCircuit {
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
impl BorshDeserialize for TrivialValidityPredicateCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let owned_resource_id = read_base_field(reader)?;
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

impl TrivialValidtyPredicateCircuitProxy {
    fn to_concrete(&self) -> Option<TrivialValidityPredicateCircuit> {
        let input_resources = self.input_resources.clone().try_into().ok()?;
        let output_resources = self.output_resources.clone().try_into().ok()?;
        let owned_resource_id = self.owned_resource_id;
        Some(TrivialValidityPredicateCircuit {
            owned_resource_id,
            input_resources,
            output_resources,
        })
    }
}
#[cfg(feature = "nif")]
impl Encoder for TrivialValidityPredicateCircuit {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_proxy().encode(env)
    }
}
#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for TrivialValidityPredicateCircuit {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let val: TrivialValidtyPredicateCircuitProxy = Decoder::decode(term)?;
        val.to_concrete()
            .ok_or(rustler::Error::RaiseAtom("Could not decode proxy"))
    }
}

impl ValidityPredicateCircuit for TrivialValidityPredicateCircuit {
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

vp_circuit_impl!(TrivialValidityPredicateCircuit);

impl ValidityPredicateVerifyingInfo for TrivialValidityPredicateCircuit {
    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&15).unwrap();
        let public_inputs = self.get_public_inputs(&mut rng);
        let proof = Proof::create(
            &TRIVIAL_VP_PK,
            params,
            self.clone(),
            &[public_inputs.inner()],
            &mut rng,
        )
        .unwrap();
        VPVerifyingInfo {
            vk: TRIVIAL_VP_PK.get_vk().clone(),
            proof,
            public_inputs,
        }
    }

    fn verify_transparently(&self) -> Result<ValidityPredicatePublicInputs, TransactionError> {
        use halo2_proofs::dev::MockProver;
        let mut rng = OsRng;
        let public_inputs = self.get_public_inputs(&mut rng);
        let prover =
            MockProver::<pallas::Base>::run(15, self, vec![public_inputs.to_vec()]).unwrap();
        prover.verify().unwrap();
        Ok(public_inputs)
    }

    fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey {
        TRIVIAL_VP_VK.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::TrivialValidityPredicateCircuit;
    use crate::{constant::NUM_RESOURCE, resource::tests::random_resource};
    use ff::Field;
    use pasta_curves::pallas;
    use rand::RngCore;
    pub fn random_trivial_vp_circuit<R: RngCore>(mut rng: R) -> TrivialValidityPredicateCircuit {
        let owned_resource_id = pallas::Base::random(&mut rng);
        let input_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        TrivialValidityPredicateCircuit::new(owned_resource_id, input_resources, output_resources)
    }

    #[test]
    fn test_halo2_trivial_vp_circuit() {
        use crate::circuit::vp_circuit::ValidityPredicateCircuit;
        use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
        use halo2_proofs::dev::MockProver;
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let circuit = random_trivial_vp_circuit(&mut rng);
        let public_inputs = circuit.get_public_inputs(&mut rng);

        let prover = MockProver::<pallas::Base>::run(
            VP_CIRCUIT_PARAMS_SIZE,
            &circuit,
            vec![public_inputs.to_vec()],
        )
        .unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
