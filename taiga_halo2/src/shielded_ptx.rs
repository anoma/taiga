use crate::circuit::resource_logic_circuit::{ResourceLogic, ResourceLogicVerifyingInfo};
use crate::compliance::{ComplianceInfo, CompliancePublicInputs};
use crate::constant::{
    COMPLIANCE_CIRCUIT_PARAMS_SIZE, COMPLIANCE_PROVING_KEY, COMPLIANCE_VERIFYING_KEY,
    MAX_DYNAMIC_RESOURCE_LOGIC_NUM, NUM_RESOURCE, SETUP_PARAMS_MAP,
};
use crate::delta_commitment::DeltaCommitment;
use crate::error::TransactionError;
use crate::executable::Executable;
use crate::merkle_tree::Anchor;
use crate::nullifier::Nullifier;
use crate::proof::Proof;
use crate::resource::{ResourceCommitment, ResourceLogics};
use halo2_proofs::plonk::Error;
use pasta_curves::pallas;
use rand::RngCore;

#[cfg(feature = "nif")]
use rustler::{Decoder, Encoder, Env, NifResult, NifStruct, Term};

#[cfg(feature = "serde")]
use serde;

use crate::circuit::resource_logic_bytecode::ApplicationByteCode;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "borsh")]
use ff::PrimeField;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShieldedPartialTransaction {
    compliances: [ComplianceVerifyingInfo; NUM_RESOURCE],
    inputs: [ResourceLogicVerifyingInfoSet; NUM_RESOURCE],
    outputs: [ResourceLogicVerifyingInfoSet; NUM_RESOURCE],
    binding_sig_r: Option<pallas::Scalar>,
    hints: Vec<u8>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Action.VerifyingInfo")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ComplianceVerifyingInfo {
    compliance_proof: Proof,
    compliance_instance: CompliancePublicInputs,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Resource.VerifyingInfo")]
pub struct ResourceLogicVerifyingInfoSet {
    app_resource_logic_verifying_info: ResourceLogicVerifyingInfo,
    app_dynamic_resource_logic_verifying_info: Vec<ResourceLogicVerifyingInfo>,
    // TODO function privacy: add verifier proof and the corresponding public inputs.
    // When the verifier proof is added, we may need to reconsider the structure of `ResourceLogicVerifyingInfo`
}

// Is easier to derive traits for
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Shielded.PTX")]
struct ShieldedPartialTransactionProxy {
    compliances: Vec<ComplianceVerifyingInfo>,
    inputs: Vec<ResourceLogicVerifyingInfoSet>,
    outputs: Vec<ResourceLogicVerifyingInfoSet>,
    binding_sig_r: Option<pallas::Scalar>,
    hints: Vec<u8>,
}

impl ShieldedPartialTransaction {
    pub fn from_bytecode<R: RngCore>(
        compliances: Vec<ComplianceInfo>,
        input_resource_app: Vec<ApplicationByteCode>,
        output_resource_app: Vec<ApplicationByteCode>,
        hints: Vec<u8>,
        mut rng: R,
    ) -> Result<Self, TransactionError> {
        let inputs: Result<Vec<_>, _> = input_resource_app
            .into_iter()
            .map(|bytecode| bytecode.generate_proofs())
            .collect();
        let outputs: Result<Vec<_>, _> = output_resource_app
            .into_iter()
            .map(|bytecode| bytecode.generate_proofs())
            .collect();
        let mut rcv_sum = pallas::Scalar::zero();
        let compliances: Vec<ComplianceVerifyingInfo> = compliances
            .iter()
            .map(|compliance_info| {
                rcv_sum += compliance_info.get_rcv();
                ComplianceVerifyingInfo::create(compliance_info, &mut rng).unwrap()
            })
            .collect();

        Ok(Self {
            compliances: compliances.try_into().unwrap(),
            inputs: inputs?.try_into().unwrap(),
            outputs: outputs?.try_into().unwrap(),
            binding_sig_r: Some(rcv_sum),
            hints,
        })
    }

    pub fn build<R: RngCore>(
        compliance_pairs: Vec<ComplianceInfo>,
        input_resource_resource_logics: Vec<ResourceLogics>,
        output_resource_resource_logics: Vec<ResourceLogics>,
        hints: Vec<u8>,
        mut rng: R,
    ) -> Result<Self, Error> {
        // Generate compliance proofs
        let mut rcv_sum = pallas::Scalar::zero();
        let compliances: Vec<ComplianceVerifyingInfo> = compliance_pairs
            .iter()
            .map(|compliance_info| {
                rcv_sum += compliance_info.get_rcv();
                ComplianceVerifyingInfo::create(compliance_info, &mut rng).unwrap()
            })
            .collect();

        // Generate input resource logic proofs
        let inputs: Vec<ResourceLogicVerifyingInfoSet> = input_resource_resource_logics
            .iter()
            .map(|input_resource_resource_logic| input_resource_resource_logic.build())
            .collect();

        // Generate output resource logic proofs
        let outputs: Vec<ResourceLogicVerifyingInfoSet> = output_resource_resource_logics
            .iter()
            .map(|output_resource_resource_logic| output_resource_resource_logic.build())
            .collect();

        Ok(Self {
            compliances: compliances.try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: outputs.try_into().unwrap(),
            binding_sig_r: Some(rcv_sum),
            hints,
        })
    }

    // verify zk proof
    pub fn verify_proof(&self) -> Result<(), TransactionError> {
        // Verify compliance proofs
        for verifying_info in self.compliances.iter() {
            verifying_info.verify()?;
        }

        // Verify resource logic proofs of input resources
        for verifying_info in self.inputs.iter() {
            verifying_info.verify()?;
        }
        // Verify resource logic proofs of output resources
        for verifying_info in self.outputs.iter() {
            verifying_info.verify()?;
        }

        Ok(())
    }

    // check the nullifiers are from compliance proofs
    fn check_nullifiers(&self) -> Result<(), TransactionError> {
        assert_eq!(NUM_RESOURCE, 2);
        let compliance_nfs = self.get_nullifiers();
        for resource_logic_info in self.inputs.iter().chain(self.outputs.iter()) {
            for nfs in resource_logic_info.get_nullifiers().iter() {
                // Check the resource logic actually uses the input resources from compliance circuits.
                if !((compliance_nfs[0].inner() == nfs[0] && compliance_nfs[1].inner() == nfs[1])
                    || (compliance_nfs[0].inner() == nfs[1] && compliance_nfs[1].inner() == nfs[0]))
                {
                    return Err(TransactionError::InconsistentNullifier);
                }
            }
        }

        for (resource_logic_info, compliance_nf) in self.inputs.iter().zip(compliance_nfs.iter()) {
            // Check the app resource logic and the sub resource logics use the same owned_resource_id in one resource
            let owned_resource_id = resource_logic_info
                .app_resource_logic_verifying_info
                .get_owned_resource_id();
            for logic_resource_logic_verifying_info in resource_logic_info
                .app_dynamic_resource_logic_verifying_info
                .iter()
            {
                if owned_resource_id != logic_resource_logic_verifying_info.get_owned_resource_id()
                {
                    return Err(TransactionError::InconsistentOwnedResourceID);
                }
            }

            // Check the owned_resource_id that resource logic uses is consistent with the nf from the compliance circuit
            if owned_resource_id != compliance_nf.inner() {
                return Err(TransactionError::InconsistentOwnedResourceID);
            }
        }
        Ok(())
    }

    // check the output cms are from compliance proofs
    fn check_resource_commitments(&self) -> Result<(), TransactionError> {
        assert_eq!(NUM_RESOURCE, 2);
        let compliance_cms = self.get_output_cms();
        for resource_logic_info in self.inputs.iter().chain(self.outputs.iter()) {
            for cms in resource_logic_info.get_resource_commitments().iter() {
                // Check the resource logic actually uses the output resources from compliance circuits.
                if !((compliance_cms[0] == cms[0] && compliance_cms[1] == cms[1])
                    || (compliance_cms[0] == cms[1] && compliance_cms[1] == cms[0]))
                {
                    return Err(TransactionError::InconsistentOutputResourceCommitment);
                }
            }
        }

        for (resource_logic_info, compliance_cm) in self.outputs.iter().zip(compliance_cms.iter()) {
            // Check that the app resource logic and the sub resource_logics use the same owned_resource_id in one resource
            let owned_resource_id = resource_logic_info
                .app_resource_logic_verifying_info
                .get_owned_resource_id();
            for logic_resource_logic_verifying_info in resource_logic_info
                .app_dynamic_resource_logic_verifying_info
                .iter()
            {
                if owned_resource_id != logic_resource_logic_verifying_info.get_owned_resource_id()
                {
                    return Err(TransactionError::InconsistentOwnedResourceID);
                }
            }

            // Check the owned_resource_id that resource logic uses is consistent with the cm from the compliance circuit
            if owned_resource_id != compliance_cm.inner() {
                return Err(TransactionError::InconsistentOwnedResourceID);
            }
        }
        Ok(())
    }

    // Conversion to the generic length proxy
    fn to_proxy(&self) -> ShieldedPartialTransactionProxy {
        ShieldedPartialTransactionProxy {
            compliances: self.compliances.to_vec(),
            inputs: self.inputs.to_vec(),
            outputs: self.outputs.to_vec(),
            binding_sig_r: self.binding_sig_r,
            hints: self.hints.clone(),
        }
    }

    pub fn get_binding_sig_r(&self) -> Option<pallas::Scalar> {
        self.binding_sig_r
    }

    pub fn get_hints(&self) -> Vec<u8> {
        self.hints.clone()
    }

    pub fn clean_private_info(&mut self) {
        self.binding_sig_r = None;
        self.hints = vec![];
    }
}

impl ShieldedPartialTransactionProxy {
    fn to_concrete(&self) -> Option<ShieldedPartialTransaction> {
        let compliances = self.compliances.clone().try_into().ok()?;
        let inputs = self.inputs.clone().try_into().ok()?;
        let outputs = self.outputs.clone().try_into().ok()?;
        Some(ShieldedPartialTransaction {
            compliances,
            inputs,
            outputs,
            binding_sig_r: self.binding_sig_r,
            hints: self.hints.clone(),
        })
    }
}

impl Executable for ShieldedPartialTransaction {
    fn execute(&self) -> Result<(), TransactionError> {
        self.verify_proof()?;
        self.check_nullifiers()?;
        self.check_resource_commitments()?;
        Ok(())
    }

    fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.compliances
            .iter()
            .map(|compliance| compliance.compliance_instance.nf)
            .collect()
    }

    fn get_output_cms(&self) -> Vec<ResourceCommitment> {
        self.compliances
            .iter()
            .map(|compliance| compliance.compliance_instance.cm)
            .collect()
    }

    fn get_delta_commitments(&self) -> Vec<DeltaCommitment> {
        self.compliances
            .iter()
            .map(|compliance| compliance.compliance_instance.delta)
            .collect()
    }

    fn get_anchors(&self) -> Vec<Anchor> {
        self.compliances
            .iter()
            .map(|compliance| compliance.compliance_instance.anchor)
            .collect()
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for ShieldedPartialTransaction {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use byteorder::WriteBytesExt;
        for compliance in self.compliances.iter() {
            compliance.serialize(writer)?;
        }

        for input in self.inputs.iter() {
            input.serialize(writer)?;
        }

        for output in self.outputs.iter() {
            output.serialize(writer)?;
        }

        // Write binding_sig_r
        match self.binding_sig_r {
            None => {
                writer.write_u8(0)?;
            }
            Some(r) => {
                writer.write_u8(1)?;
                writer.write_all(&r.to_repr())?;
            }
        };

        self.hints.serialize(writer)?;

        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ShieldedPartialTransaction {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        use byteorder::ReadBytesExt;
        let compliances: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| ComplianceVerifyingInfo::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let inputs: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| ResourceLogicVerifyingInfoSet::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let outputs: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| ResourceLogicVerifyingInfoSet::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let binding_sig_r_type = reader.read_u8()?;
        let binding_sig_r = if binding_sig_r_type == 0 {
            None
        } else {
            let r = crate::utils::read_scalar_field(reader)?;
            Some(r)
        };

        let hints = Vec::<u8>::deserialize_reader(reader)?;
        Ok(ShieldedPartialTransaction {
            compliances: compliances.try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: outputs.try_into().unwrap(),
            binding_sig_r,
            hints,
        })
    }
}

#[cfg(feature = "nif")]
impl Encoder for ShieldedPartialTransaction {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_proxy().encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for ShieldedPartialTransaction {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let val: ShieldedPartialTransactionProxy = Decoder::decode(term)?;
        val.to_concrete()
            .ok_or(rustler::Error::RaiseAtom("Could not decode proxy"))
    }
}

impl ComplianceVerifyingInfo {
    pub fn create<R: RngCore>(compliance_info: &ComplianceInfo, mut rng: R) -> Result<Self, Error> {
        let (compliance_instance, circuit) = compliance_info.build();
        let params = SETUP_PARAMS_MAP
            .get(&COMPLIANCE_CIRCUIT_PARAMS_SIZE)
            .unwrap();
        let compliance_proof = Proof::create(
            &COMPLIANCE_PROVING_KEY,
            params,
            circuit,
            &[&compliance_instance.to_instance()],
            &mut rng,
        )?;
        Ok(Self {
            compliance_proof,
            compliance_instance,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        let params = SETUP_PARAMS_MAP
            .get(&COMPLIANCE_CIRCUIT_PARAMS_SIZE)
            .unwrap();
        self.compliance_proof.verify(
            &COMPLIANCE_VERIFYING_KEY,
            params,
            &[&self.compliance_instance.to_instance()],
        )
    }
}

impl ResourceLogicVerifyingInfoSet {
    pub fn new(
        app_resource_logic_verifying_info: ResourceLogicVerifyingInfo,
        app_dynamic_resource_logic_verifying_info: Vec<ResourceLogicVerifyingInfo>,
    ) -> Self {
        assert!(app_dynamic_resource_logic_verifying_info.len() <= MAX_DYNAMIC_RESOURCE_LOGIC_NUM);

        Self {
            app_resource_logic_verifying_info,
            app_dynamic_resource_logic_verifying_info,
        }
    }

    // TODO: remove it.
    pub fn build(
        application_resource_logic: Box<ResourceLogic>,
        dynamic_resource_logics: Vec<Box<ResourceLogic>>,
    ) -> Self {
        assert!(dynamic_resource_logics.len() <= MAX_DYNAMIC_RESOURCE_LOGIC_NUM);

        let app_resource_logic_verifying_info = application_resource_logic.get_verifying_info();

        let app_dynamic_resource_logic_verifying_info = dynamic_resource_logics
            .into_iter()
            .map(|verifying_info| verifying_info.get_verifying_info())
            .collect();

        Self {
            app_resource_logic_verifying_info,
            app_dynamic_resource_logic_verifying_info,
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        // Verify the application resource logic proof
        self.app_resource_logic_verifying_info.verify()?;

        // Verify application dynamic resource logic proofs
        for verify_info in self.app_dynamic_resource_logic_verifying_info.iter() {
            verify_info.verify()?;
        }

        // TODO function privacy: Verify resource logic verifier proofs

        Ok(())
    }

    pub fn get_nullifiers(&self) -> Vec<[pallas::Base; NUM_RESOURCE]> {
        let mut nfs = vec![self.app_resource_logic_verifying_info.get_nullifiers()];
        self.app_dynamic_resource_logic_verifying_info
            .iter()
            .for_each(|resource_logic_info| nfs.push(resource_logic_info.get_nullifiers()));
        nfs
    }

    pub fn get_resource_commitments(&self) -> Vec<[ResourceCommitment; NUM_RESOURCE]> {
        let mut cms = vec![self
            .app_resource_logic_verifying_info
            .get_resource_commitments()];
        self.app_dynamic_resource_logic_verifying_info
            .iter()
            .for_each(|resource_logic_info| {
                cms.push(resource_logic_info.get_resource_commitments())
            });
        cms
    }
}

#[cfg(test)]
pub mod testing {
    use crate::{
        circuit::resource_logic_circuit::{ResourceLogic, ResourceLogicVerifyingInfoTrait},
        circuit::resource_logic_examples::TrivialResourceLogicCircuit,
        compliance::ComplianceInfo,
        constant::TAIGA_COMMITMENT_TREE_DEPTH,
        merkle_tree::MerklePath,
        nullifier::Nullifier,
        resource::{Resource, ResourceLogics},
        shielded_ptx::ShieldedPartialTransaction,
        utils::poseidon_hash,
    };
    use halo2_proofs::arithmetic::Field;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    pub fn create_shielded_ptx() -> ShieldedPartialTransaction {
        let mut rng = OsRng;

        // Create empty resource logic circuit without resource info
        let trivial_resource_logic_circuit = TrivialResourceLogicCircuit::default();
        let trivial_resource_logic_vk = trivial_resource_logic_circuit.get_resource_logic_vk();
        let compressed_trivial_resource_logic_vk = trivial_resource_logic_vk.get_compressed();

        // Generate resources
        let input_resource_1 = {
            let label = pallas::Base::zero();
            // TODO: add real application dynamic resource logics and encode them to value later.
            let app_dynamic_resource_logic_vk = [
                compressed_trivial_resource_logic_vk,
                compressed_trivial_resource_logic_vk,
            ];
            // Encode the app_dynamic_resource_logic_vk into value
            // The encoding method is flexible and defined in the application resource logic.
            // Use poseidon hash to encode the two dynamic resource logics here
            let value = poseidon_hash(
                app_dynamic_resource_logic_vk[0],
                app_dynamic_resource_logic_vk[1],
            );
            let nonce = Nullifier::from(pallas::Base::random(&mut rng));
            let quantity = 5000u64;
            let nk = pallas::Base::random(&mut rng);
            let rseed = pallas::Base::random(&mut rng);
            let is_ephemeral = false;
            Resource::new_input_resource(
                compressed_trivial_resource_logic_vk,
                label,
                value,
                quantity,
                nk,
                nonce,
                is_ephemeral,
                rseed,
            )
        };
        let mut output_resource_1 = {
            let label = pallas::Base::zero();
            // TODO: add real application dynamic resource logics and encode them to value later.
            // If the dynamic resource logic is not used, set value pallas::Base::zero() by default.
            let value = pallas::Base::zero();
            let quantity = 5000u64;
            let npk = pallas::Base::random(&mut rng);
            let rseed = pallas::Base::random(&mut rng);
            let is_ephemeral = false;
            Resource::new_output_resource(
                compressed_trivial_resource_logic_vk,
                label,
                value,
                quantity,
                npk,
                is_ephemeral,
                rseed,
            )
        };

        // Construct compliance pair
        let merkle_path_1 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let compliance_1 = ComplianceInfo::new(
            input_resource_1,
            merkle_path_1,
            None,
            &mut output_resource_1,
            &mut rng,
        );

        // Generate resources
        let input_resource_2 = {
            let label = pallas::Base::one();
            let value = pallas::Base::zero();
            let nonce = Nullifier::from(pallas::Base::random(&mut rng));
            let quantity = 10u64;
            let nk = pallas::Base::random(&mut rng);
            let rseed = pallas::Base::random(&mut rng);
            let is_ephemeral = false;
            Resource::new_input_resource(
                compressed_trivial_resource_logic_vk,
                label,
                value,
                quantity,
                nk,
                nonce,
                is_ephemeral,
                rseed,
            )
        };
        let mut output_resource_2 = {
            let label = pallas::Base::one();
            let value = pallas::Base::zero();
            let quantity = 10u64;
            let npk = pallas::Base::random(&mut rng);
            let rseed = pallas::Base::random(&mut rng);
            let is_ephemeral = false;
            Resource::new_output_resource(
                compressed_trivial_resource_logic_vk,
                label,
                value,
                quantity,
                npk,
                is_ephemeral,
                rseed,
            )
        };

        // Construct compliance pair
        let merkle_path_2 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let compliance_2 = ComplianceInfo::new(
            input_resource_2,
            merkle_path_2,
            None,
            &mut output_resource_2,
            &mut rng,
        );

        // Create resource logic circuit and fill the resource info
        let mut trivial_resource_logic_circuit = TrivialResourceLogicCircuit {
            owned_resource_id: input_resource_1.get_nf().unwrap().inner(),
            input_resources: [input_resource_1, input_resource_2],
            output_resources: [output_resource_1, output_resource_2],
        };
        let input_application_resource_logic_1 = Box::new(trivial_resource_logic_circuit.clone());
        let trivial_app_logic_1: Box<ResourceLogic> =
            Box::new(trivial_resource_logic_circuit.clone());
        let trivial_app_logic_2 = Box::new(trivial_resource_logic_circuit.clone());
        let trivial_dynamic_resource_logics = vec![trivial_app_logic_1, trivial_app_logic_2];
        let input_resource_1_resource_logics = ResourceLogics::new(
            input_application_resource_logic_1,
            trivial_dynamic_resource_logics,
        );

        // The following resources use empty logic resource_logics and use value with pallas::Base::zero() by default.
        trivial_resource_logic_circuit.owned_resource_id =
            input_resource_2.get_nf().unwrap().inner();
        let input_application_resource_logic_2 = Box::new(trivial_resource_logic_circuit.clone());
        let input_resource_2_resource_logics =
            ResourceLogics::new(input_application_resource_logic_2, vec![]);

        trivial_resource_logic_circuit.owned_resource_id = output_resource_1.commitment().inner();
        let output_application_resource_logic_1 = Box::new(trivial_resource_logic_circuit.clone());
        let output_resource_1_resource_logics =
            ResourceLogics::new(output_application_resource_logic_1, vec![]);

        trivial_resource_logic_circuit.owned_resource_id = output_resource_2.commitment().inner();
        let output_application_resource_logic_2 = Box::new(trivial_resource_logic_circuit);
        let output_resource_2_resource_logics =
            ResourceLogics::new(output_application_resource_logic_2, vec![]);

        // Create shielded partial tx
        ShieldedPartialTransaction::build(
            vec![compliance_1, compliance_2],
            vec![
                input_resource_1_resource_logics,
                input_resource_2_resource_logics,
            ],
            vec![
                output_resource_1_resource_logics,
                output_resource_2_resource_logics,
            ],
            vec![],
            &mut rng,
        )
        .unwrap()
    }
}
