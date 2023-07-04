use std::collections::HashMap;

use ff::Field;
use halo2_proofs::{circuit::Value, poly::commitment::Params};
use pasta_curves::pallas;

use crate::{note::{NoteCommitment, Note, ValueBase, InputNoteProvingInfo, OutputNoteProvingInfo}, merkle_tree::{MerklePath, Node, MerkleTreeLeafs}, circuit::{vp_circuit::ValidityPredicateCircuit, note_circuit::NoteConfig}, vp_circuit_impl, constant::NUM_NOTE, note_encryption::NoteCipher};


enum APIError {
    GenericError,
    NoteDecryptionError
}

struct NoteInTree {
    note: Note,
    note_cm: NoteCommitment,
    merkle_path: MerklePath,
    merkle_root: Node
}
pub trait APIContext {
    type EncryptedNotesStorage;
    type NoteTypeDirectory;

    pub fn retrieve_note_type_directory() -> Result<NoteTypeDirectory, APIError>;
    pub fn retrieve_decrypted_note(note_comm: NoteCommitment) -> Result<Note, APIError>;
    pub fn retrieve_note_type(name: string, directory: NoteTypeDirectory) -> Option<ValueBase>;
    pub fn retrieve_merkle_tree() -> Result<MerkleTreeLeafs, APIError>;
    pub fn retrieve_owned_notes() -> Result<vec<NoteInTree>, APIError>;
    pub fn create_ptx(input_proving_info: [InputNoteProvingInfo; 2], output_proving_info: [OutputNoteProvingInfo; 2]) -> Result<(), APIError>;
}

struct TestContext;

impl APIContext for TestContext {
    type EncryptedNotesStorage = HashMap<NoteCommitment, NoteCipher>;
    type NoteTypeDirectory = HashMap<string, (ValueBase, ValidityPredicateCircuit, Params<pallas::Base>)>;
    fn retrieve_note_type_directory() -> Result<NoteTypeDirectory, APIError> {
        // Construct directory
        let directory = NoteTypeDirectory::new();
        OK(directory)
    }
    
    fn retrieve_merkle_tree() -> Result<MerkleTreeLeafs, APIError> {
        // Construct Merkle Tree
        // Insert banana, apple, pear, grapefruit
        Err(APIError::GenericError)
    }
    
    fn retrieve_note_type(name: string, directory: NoteTypeDirectory) -> Option<ValueBase> {
        let (note_type, circuit, params) = directory.get(name).unwrap();
        // Maybe check that the value base corresponds to the circuit
        Some(note_type)
    }
    
    fn retrieve_owned_notes(note_type: ValueBase, sk: pallas::Scalar, merkle_tree_leaves: MerkleTreeLeafs) -> Result<vec<(NoteCommitment, Note, MerklePath, Node)>, APIError> {
        // TODO: Try to decrypt all note commitments in the merkle_tree_leaves
        Err(APIError::GenericError)
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


