#[cfg(feature = "borsh")]
use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
use crate::error::TransactionError;
use crate::shielded_ptx::NoteVPVerifyingInfoSet;
use crate::{
    circuit::vp_circuit::{
        VPVerifyingInfo, ValidityPredicateVerifyingInfo, VampIRValidityPredicateCircuit,
    },
    constant::{
        VP_CIRCUIT_NULLIFIER_ONE_PUBLIC_INPUT_IDX, VP_CIRCUIT_NULLIFIER_TWO_PUBLIC_INPUT_IDX,
        VP_CIRCUIT_OUTPUT_CM_ONE_PUBLIC_INPUT_IDX, VP_CIRCUIT_OUTPUT_CM_TWO_PUBLIC_INPUT_IDX,
        VP_CIRCUIT_OWNED_NOTE_PUB_ID_PUBLIC_INPUT_IDX,
    },
    note::NoteCommitment,
    nullifier::Nullifier,
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
            #[allow(unreachable_patterns)]
            _ => Err(TransactionError::InvalidValidityPredicateRepresentation),
        }
    }

    // Verify vp circuit transparently and return owned note PubID for further checking
    pub fn verify_transparently(
        &self,
        action_nfs: &[Nullifier],
        action_cms: &[NoteCommitment],
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
            #[allow(unreachable_patterns)]
            _ => return Err(TransactionError::InvalidValidityPredicateRepresentation),
        };

        // check nullifiers
        // Check the vp actually uses the input notes from action circuits.
        let vp_nfs = [
            public_inputs.get_from_index(VP_CIRCUIT_NULLIFIER_ONE_PUBLIC_INPUT_IDX),
            public_inputs.get_from_index(VP_CIRCUIT_NULLIFIER_TWO_PUBLIC_INPUT_IDX),
        ];

        if !((action_nfs[0].inner() == vp_nfs[0] && action_nfs[1].inner() == vp_nfs[1])
            || (action_nfs[0].inner() == vp_nfs[1] && action_nfs[1].inner() == vp_nfs[0]))
        {
            return Err(TransactionError::InconsistentNullifier);
        }

        // check note_commitments
        // Check the vp actually uses the output notes from action circuits.
        let vp_cms = [
            public_inputs.get_from_index(VP_CIRCUIT_OUTPUT_CM_ONE_PUBLIC_INPUT_IDX),
            public_inputs.get_from_index(VP_CIRCUIT_OUTPUT_CM_TWO_PUBLIC_INPUT_IDX),
        ];
        if !((action_cms[0].inner() == vp_cms[0] && action_cms[1].inner() == vp_cms[1])
            || (action_cms[0].inner() == vp_cms[1] && action_cms[1].inner() == vp_cms[0]))
        {
            return Err(TransactionError::InconsistentOutputNoteCommitment);
        }

        Ok(public_inputs.get_from_index(VP_CIRCUIT_OWNED_NOTE_PUB_ID_PUBLIC_INPUT_IDX))
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

    pub fn generate_proofs(self) -> Result<NoteVPVerifyingInfoSet, TransactionError> {
        let app_vp_verifying_info = self.app_vp_bytecode.generate_proof()?;

        let app_dynamic_vp_verifying_info: Result<Vec<_>, _> = self
            .dynamic_vp_bytecode
            .into_iter()
            .map(|bytecode| bytecode.generate_proof())
            .collect();
        Ok(NoteVPVerifyingInfoSet::new(
            app_vp_verifying_info,
            app_dynamic_vp_verifying_info?,
        ))
    }

    // Verify vp circuits transparently and return owned note PubID for further checking
    pub fn verify_transparently(
        &self,
        action_nfs: &[Nullifier],
        action_cms: &[NoteCommitment],
    ) -> Result<pallas::Base, TransactionError> {
        let owned_note_id = self
            .app_vp_bytecode
            .verify_transparently(action_nfs, action_cms)?;
        for dynamic_vp in self.dynamic_vp_bytecode.iter() {
            let id = dynamic_vp.verify_transparently(action_nfs, action_cms)?;
            // check: the app_vp and dynamic_vps belong to the note
            if id != owned_note_id {
                return Err(TransactionError::InconsistentOwnedNotePubID);
            }
        }
        Ok(owned_note_id)
    }
}
