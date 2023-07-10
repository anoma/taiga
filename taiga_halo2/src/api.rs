mod notes;

use std::collections::HashMap;

use ff::Field;
use group::{Group, Curve};
use halo2_proofs::{circuit::Value, poly::commitment::Params};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas::Affine;
use pasta_curves::{pallas, Fp};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::circuit::vp_examples::cascade_intent::create_intent_note;
use crate::circuit::vp_examples::receiver_vp::decrypt_note;
use crate::circuit::vp_examples::token::{TokenValidityPredicateCircuit, generate_input_token_note_proving_info, create_token_note};
use crate::nullifier::Nullifier;
use crate::shielded_ptx::{NoteVPVerifyingInfoSet, ShieldedPartialTransaction};
use crate::utils::mod_r_p;
use crate::{
    circuit::{note_circuit::NoteConfig, vp_circuit::ValidityPredicateCircuit},
    constant::NUM_NOTE,
    merkle_tree::{MerklePath, MerkleTreeLeaves, Node},
    note::{InputNoteProvingInfo, Note, NoteCommitment, OutputNoteProvingInfo, ValueBase},
    note_encryption::NoteCipher,
    vp_circuit_impl,
};

pub enum APIError {
    GenericError,
    NoteDecryptionError,
    RetrieveNoteError
}

pub struct NoteInTree {
    note: Note,
    note_cm: pallas::Base,
    merkle_path: MerklePath,
}

pub struct ProvingInfo {
    input_proving_info: [InputNoteProvingInfo; 2],
    output_proving_info: [OutputNoteProvingInfo; 2]
}

pub trait APIContext {
    fn decrypt_note(&self, note_comm: pallas::Base, public_key: pallas::Affine, private_key: pallas::Base) -> Result<Note, APIError>;
    fn retrieve_note_type(&self, name: &str) -> Option<ValueBase>;
    fn retrieve_owned_notes(
        &self,
        note_identifiers: Vec<String>,
        sk: pallas::Base,
        pk: pallas::Affine
    ) -> Result<Vec<(String, Vec<NoteInTree>)>, APIError> ;
    fn create_ptx(proving_info: ProvingInfo) -> Result<ShieldedPartialTransaction, APIError>;
    fn finalize_tx(partial_transactions: Vec<ShieldedPartialTransaction>) -> Result<(), APIError>;
}

struct VPCircuit {}

/// An APIContext that with in-memory storage
struct TestContext {
    note_directory: HashMap<String, (ValueBase, VPCircuit, Fp)>,
    // Does the note_directory need to be generic on the circuit type,
    // or do we expect to return a single impl of ValidityPredicateCircuit?
    encrypted_notes_directory: HashMap<String, NoteCipher>,
    note_commitment_tree: MerkleTreeLeaves,
}

impl APIContext for TestContext {
    fn decrypt_note(&self, note_comm: pallas::Base, pk: pallas::Affine, sk: pallas::Base) -> Result<Note, APIError> {
        let s = format!("{:?}", note_comm);
        match self.encrypted_notes_directory.get(&s) {
            Some(encrypted_note) => {
                let pk_coordinates = pk.coordinates().unwrap();
                let instances = vec![note_comm, *pk_coordinates.x(), *pk_coordinates.y()];
                match decrypt_note(instances, sk) {
                    Some(decrypted_note) => Ok(decrypted_note),
                    None => Err(APIError::NoteDecryptionError)
                }
            },
            None => Err(APIError::NoteDecryptionError)
        }
    }

    fn retrieve_note_type(&self, name: &str) -> Option<ValueBase> {
        let (note_type, circuit, params) = self.note_directory.get(name).unwrap();
        // Maybe check that the value base corresponds to the circuit
        Some(note_type.clone())
    }

    fn retrieve_owned_notes(
        &self,
        note_identifiers: Vec<String>,
        sk: pallas::Base,
        pk: pallas::Affine
    ) -> Result<Vec<(String, Vec<NoteInTree>)>, APIError> {
        note_identifiers.iter().map(|note_identifier| {
            let retrieved = match self.retrieve_note_type(note_identifier.as_str()) {
                Some(note_type) => {
                    let owned_notes = self.note_commitment_tree.get_leaves().iter().enumerate().filter_map(|(i, node)| {
                        match self.decrypt_note(node.inner(), pk, sk) {
                            Ok(note) => if note.get_value_base() == note_type.derive_value_base() {
                                let merkle_path = MerklePath::build_merkle_path(&self.note_commitment_tree.get_leaves(), i);
                                Some(NoteInTree {
                                    note,
                                    note_cm:  node.inner(),
                                    merkle_path
                                })
                            } else {
                                None
                            }
                            Err(_) => None
                        }
                    }).collect::<Vec<_>>();
                    Some((note_identifier.clone(), owned_notes))
                }
                None => None
            };
            match retrieved {
                Some((note_identifier, owned_notes)) => Ok((note_identifier.clone(), owned_notes)),
                None => Err(APIError::RetrieveNoteError)
            }
        }).collect()
    }
    

    fn create_ptx(
        proving_info: ProvingInfo,
    ) -> Result<ShieldedPartialTransaction, APIError> {
        todo!()
    }

    fn finalize_tx(partial_transactions: Vec<ShieldedPartialTransaction>) -> Result<(), APIError> {
        todo!()
    }
}

pub fn keygen(rng: &mut OsRng) -> (pallas::Base, pallas::Point)  {
    // Private key: sk
    let sk = pallas::Base::random(rng);
    let generator = pallas::Point::generator().to_affine();
    let pk = generator * mod_r_p(sk);
    (sk, pk)
}

pub fn main() {
    let mut rng = OsRng;
    // Alice keys
    let (sk, pk) = keygen(&mut rng); 
    let rho = Nullifier::new(pallas::Base::random(&mut rng));
    // let input_nk_com = NullifierKeyCom::from_open(input_nk);

    // let input_token_note_1 = create_token_note(
    //     input_token,
    //     input_value,
    //     rho,
    //     input_nk_com,
    //     &input_auth,
    // );

    // let input_proving_info_1 = generate_input_token_note_proving_info(rng, input_note, token_name, auth, auth_sk, merkle_path, input_notes, output_notes);
    // let input_proving_info_2 = generate_input_token_note_proving_info(rng, input_note, token_name, auth, auth_sk, merkle_path, input_notes, output_notes);

    // let intent_note = create_intent_note(rng, cascade_note_cm, rho, nk_com);

    // Exchange a banana for an apple or a pear for a grapefruit
    // Alice steps (example):
    // Find what she owns
    // - find note_type
    // - retrieve_my_notes
    // Find what she wants
}

