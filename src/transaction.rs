use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt};
use crate::{action::Action, note::Note, CircuitParameters};
use blake2::crypto_mac::Mac;
use crate::action;
use plonk::proof_system::Verifier;
use rs_merkle::{MerkleTree, Hasher, algorithms::Sha256};
use crate::circuit::validity_predicate::ValidityPredicate;

pub struct Transaction<CP: CircuitParameters> {
    _max: usize, // the maximum number of actions/notes for a transaction
    _actions: Vec<Action<CP>>,
    _spent_notes: Vec<Note<CP>>,
    _created_notes: Vec<Note<CP>>,
    vps: Vec<ValidityPredicate<CP>>
}

impl<CP: CircuitParameters> Transaction<CP> {
    fn _process(&self, nftree: &mut MerkleTree<Sha256>, mttree: &mut MerkleTree<Sha256>) {
        //todo: extract the check?
        //todo: add action check

        //verify validity predicates;
        //todo: update to verification of blinded vps
        //todo: add blinding circuit check
        for vp in &self.vps {
            vp.verify()
        }

        for i in &self._created_notes {
            //add nullifiers to the nullifier tree
            let mut nf_hash = vec![];
            i.spent_note_nf.serialize_unchecked(&mut nf_hash).unwrap();
            let hash = Sha256::hash(nf_hash.as_slice());
            nftree.insert(hash);
            nftree.commit();

            //todo: add commitments to the commitment tree
        }

        // check that a transaction is valid, and add new notes to the trees
        // todo
        assert!(self._actions.len() < self._max);
        assert!(self._spent_notes.len() < self._max);
    }
}
