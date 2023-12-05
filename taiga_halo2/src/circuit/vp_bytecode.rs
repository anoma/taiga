#[cfg(feature = "examples")]
use crate::circuit::vp_examples::token::TokenValidityPredicateCircuit;
#[cfg(feature = "borsh")]
use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
use crate::error::TransactionError;
use crate::shielded_ptx::ResourceVPVerifyingInfoSet;
use crate::{
    circuit::vp_circuit::{
        VPVerifyingInfo, ValidityPredicateVerifyingInfo, VampIRValidityPredicateCircuit,
    },
    constant::{
        VP_CIRCUIT_NULLIFIER_ONE_PUBLIC_INPUT_IDX, VP_CIRCUIT_NULLIFIER_TWO_PUBLIC_INPUT_IDX,
        VP_CIRCUIT_OUTPUT_CM_ONE_PUBLIC_INPUT_IDX, VP_CIRCUIT_OUTPUT_CM_TWO_PUBLIC_INPUT_IDX,
        VP_CIRCUIT_OWNED_RESOURCE_ID_PUBLIC_INPUT_IDX,
    },
    nullifier::Nullifier,
    resource::ResourceCommitment,
};

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use pasta_curves::pallas;
#[cfg(feature = "serde")]
use serde;
use std::path::PathBuf;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ValidityPredicateRepresentation {
    // vampir has a unified circuit representation.
    VampIR(Vec<u8>),
    // Native halo2 circuits don't have a unified representatioin, enumerate the vp circuit examples for the moment.
    // TODO: figure out if we can have a unified circuit presentation. In theory, it's possible to separate the circuit system and proving system.
    Trivial,
    Token,
    // TODO: add other vp types here if needed
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidityPredicateByteCode {
    circuit: ValidityPredicateRepresentation,
    inputs: Vec<u8>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationByteCode {
    app_vp_bytecode: ValidityPredicateByteCode,
    dynamic_vp_bytecode: Vec<ValidityPredicateByteCode>,
}

impl ValidityPredicateByteCode {
    pub fn new(circuit: ValidityPredicateRepresentation, inputs: Vec<u8>) -> Self {
        Self { circuit, inputs }
    }

    pub fn generate_proof(self) -> Result<VPVerifyingInfo, TransactionError> {
        match self.circuit {
            ValidityPredicateRepresentation::VampIR(circuit) => {
                // TDDO: use the file_name api atm,
                // request vamp_ir to provide a api to generate circuit from bytes.
                let vamp_ir_circuit_file =
                    PathBuf::from(String::from_utf8_lossy(&circuit).to_string());
                let inputs_file = PathBuf::from(String::from_utf8_lossy(&self.inputs).to_string());
                let vp_circuit = VampIRValidityPredicateCircuit::from_vamp_ir_file(
                    &vamp_ir_circuit_file,
                    &inputs_file,
                );
                Ok(vp_circuit.get_verifying_info())
            }
            #[cfg(feature = "borsh")]
            ValidityPredicateRepresentation::Trivial => {
                let vp = TrivialValidityPredicateCircuit::from_bytes(&self.inputs);
                Ok(vp.get_verifying_info())
            }
            #[cfg(feature = "examples")]
            ValidityPredicateRepresentation::Token => {
                let vp = TokenValidityPredicateCircuit::from_bytes(&self.inputs);
                Ok(vp.get_verifying_info())
            }
            #[allow(unreachable_patterns)]
            _ => Err(TransactionError::InvalidValidityPredicateRepresentation),
        }
    }

    // Verify vp circuit transparently and return owned resource PubID for further checking
    pub fn verify_transparently(
        &self,
        compliance_nfs: &[Nullifier],
        compliance_cms: &[ResourceCommitment],
    ) -> Result<pallas::Base, TransactionError> {
        // check VP transparently
        let public_inputs = match &self.circuit {
            ValidityPredicateRepresentation::VampIR(circuit) => {
                // TDDO: use the file_name api atm,
                // request vamp_ir to provide a api to generate circuit from bytes.
                let vamp_ir_circuit_file =
                    PathBuf::from(String::from_utf8_lossy(circuit).to_string());
                let inputs_file = PathBuf::from(String::from_utf8_lossy(&self.inputs).to_string());
                let vp_circuit = VampIRValidityPredicateCircuit::from_vamp_ir_file(
                    &vamp_ir_circuit_file,
                    &inputs_file,
                );
                vp_circuit.verify_transparently()?
            }
            #[cfg(feature = "borsh")]
            ValidityPredicateRepresentation::Trivial => {
                let vp = TrivialValidityPredicateCircuit::from_bytes(&self.inputs);
                vp.verify_transparently()?
            }
            #[cfg(feature = "examples")]
            ValidityPredicateRepresentation::Token => {
                let vp = TokenValidityPredicateCircuit::from_bytes(&self.inputs);
                vp.verify_transparently()?
            }
            #[allow(unreachable_patterns)]
            _ => return Err(TransactionError::InvalidValidityPredicateRepresentation),
        };

        // check nullifiers
        // Check the vp actually uses the input resources from compliance circuits.
        let vp_nfs = [
            public_inputs.get_from_index(VP_CIRCUIT_NULLIFIER_ONE_PUBLIC_INPUT_IDX),
            public_inputs.get_from_index(VP_CIRCUIT_NULLIFIER_TWO_PUBLIC_INPUT_IDX),
        ];

        if !((compliance_nfs[0].inner() == vp_nfs[0] && compliance_nfs[1].inner() == vp_nfs[1])
            || (compliance_nfs[0].inner() == vp_nfs[1] && compliance_nfs[1].inner() == vp_nfs[0]))
        {
            return Err(TransactionError::InconsistentNullifier);
        }

        // check resource_commitments
        // Check the vp actually uses the output resources from compliance circuits.
        let vp_cms = [
            public_inputs.get_from_index(VP_CIRCUIT_OUTPUT_CM_ONE_PUBLIC_INPUT_IDX),
            public_inputs.get_from_index(VP_CIRCUIT_OUTPUT_CM_TWO_PUBLIC_INPUT_IDX),
        ];
        if !((compliance_cms[0].inner() == vp_cms[0] && compliance_cms[1].inner() == vp_cms[1])
            || (compliance_cms[0].inner() == vp_cms[1] && compliance_cms[1].inner() == vp_cms[0]))
        {
            return Err(TransactionError::InconsistentOutputResourceCommitment);
        }

        Ok(public_inputs.get_from_index(VP_CIRCUIT_OWNED_RESOURCE_ID_PUBLIC_INPUT_IDX))
    }
}

impl ApplicationByteCode {
    pub fn new(
        app_vp_bytecode: ValidityPredicateByteCode,
        dynamic_vp_bytecode: Vec<ValidityPredicateByteCode>,
    ) -> Self {
        Self {
            app_vp_bytecode,
            dynamic_vp_bytecode,
        }
    }

    pub fn generate_proofs(self) -> Result<ResourceVPVerifyingInfoSet, TransactionError> {
        let app_vp_verifying_info = self.app_vp_bytecode.generate_proof()?;

        let app_dynamic_vp_verifying_info: Result<Vec<_>, _> = self
            .dynamic_vp_bytecode
            .into_iter()
            .map(|bytecode| bytecode.generate_proof())
            .collect();
        Ok(ResourceVPVerifyingInfoSet::new(
            app_vp_verifying_info,
            app_dynamic_vp_verifying_info?,
        ))
    }

    // Verify vp circuits transparently and return owned resource PubID for further checking
    pub fn verify_transparently(
        &self,
        compliance_nfs: &[Nullifier],
        compliance_cms: &[ResourceCommitment],
    ) -> Result<pallas::Base, TransactionError> {
        let owned_resource_id = self
            .app_vp_bytecode
            .verify_transparently(compliance_nfs, compliance_cms)?;
        for dynamic_vp in self.dynamic_vp_bytecode.iter() {
            let id = dynamic_vp.verify_transparently(compliance_nfs, compliance_cms)?;
            // check: the app_vp and dynamic_vps belong to the resource
            if id != owned_resource_id {
                return Err(TransactionError::InconsistentOwneResourceID);
            }
        }
        Ok(owned_resource_id)
    }
}
