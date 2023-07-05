use std::collections::HashMap;

use ff::Field;
use halo2_proofs::{circuit::Value, poly::commitment::Params};
use pasta_curves::{pallas, Fp};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::circuit::vp_examples::token::TokenValidityPredicateCircuit;
use crate::shielded_ptx::NoteVPVerifyingInfoSet;
use crate::{
    circuit::{note_circuit::NoteConfig, vp_circuit::ValidityPredicateCircuit},
    constant::NUM_NOTE,
    merkle_tree::{MerklePath, MerkleTreeLeafs, Node},
    note::{InputNoteProvingInfo, Note, NoteCommitment, OutputNoteProvingInfo, ValueBase},
    note_encryption::NoteCipher,
    vp_circuit_impl,
};

pub enum APIError {
    GenericError,
    NoteDecryptionError,
}

pub struct NoteInTree {
    note: Note,
    note_cm: NoteCommitment,
    merkle_path: MerklePath,
    merkle_root: Node,
}

pub struct PartialTransaction {
    input_proving_info: [InputNoteProvingInfo; 2],
    output_proving_info: [OutputNoteProvingInfo; 2]
}

pub trait APIContext {
    fn retrieve_decrypted_note(note_comm: NoteCommitment) -> Result<Note, APIError>;
    fn retrieve_note_type(&self, name: &str) -> Option<ValueBase>;
    fn retrieve_owned_notes(
        &self,
        note_type: ValueBase,
        sk: pallas::Scalar,
    ) -> Result<Vec<NoteInTree>, APIError>;
    fn create_ptx(
        PartialTransaction,
    ) -> Result<PartialTransaction, APIError>;
    fn finalize_tx(partial_transactions: Vec<PartialTransaction>) -> Result<(), APIError>;
}

struct VPCircuit {}

/// An APIContext that with in-memory storage
struct TestContext {
    note_directory: HashMap<String, (ValueBase, VPCircuit, Fp)>,
    // Does the note_directory need to be generic on the circuit type,
    // or do we expect to return a single impl of ValidityPredicateCircuit?
    decrypted_notes: HashMap<NoteCommitment, NoteCipher>,
    merkle_tree_leafs: MerkleTreeLeafs,
}

impl APIContext for TestContext {
    fn retrieve_decrypted_note(note_comm: NoteCommitment) -> Result<Note, APIError> {
        todo!()
    }

    fn retrieve_note_type(&self, name: &str) -> Option<ValueBase> {
        let (note_type, circuit, params) = self.note_directory.get(name).unwrap();
        // Maybe check that the value base corresponds to the circuit
        Some(note_type.clone())
    }

    fn retrieve_owned_notes(
        &self,
        note_type: ValueBase,
        sk: pallas::Scalar,
    ) -> Result<Vec<NoteInTree>, APIError> {
        // TODO: Try to decrypt all note commitments in the merkle_tree_leaves
        Err(APIError::GenericError)
    }

    fn create_ptx(
        partial_transaction: PartialTransaction,
    ) -> Result<PartialTransaction, APIError> {
        todo!()
    }

    fn finalize_tx(partial_transactions: Vec<PartialTransaction>) -> Result<(), APIError> {
        todo!()
    }
}

pub fn main() {
    // Alice keys
    let mut rng = OsRng;
    // Private key: sk
    let sk = pallas::Scalar::from(rng.next_u64());

    // Exchange a banana for an apple or a pear for a grapefruit
    // Alice steps (example):
    // Find what she owns
    // - find note_type
    // - retrieve_my_notes
    // Find what she wants
}
