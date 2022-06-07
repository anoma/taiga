use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt};
use crate::{action::Action, note::Note, CircuitParameters, add_to_tree, serializable_to_vec, serializable_to_array};
use blake2::crypto_mac::Mac;
use crate::action;
use rs_merkle::{MerkleTree, Hasher, algorithms::Sha256};
use crate::circuit::validity_predicate::ValidityPredicate;
use plonk_core::proof_system::Verifier;

pub struct Transaction<CP: CircuitParameters> {
    _max: usize, // the maximum number of actions/notes for a transaction
    _actions: Vec<Action<CP>>,
    _spent_notes: Vec<Note<CP>>,
    _created_notes: Vec<Note<CP>>,
    vps: Vec<ValidityPredicate<CP>>
}

impl<CP: CircuitParameters> Transaction<CP> {
    fn check(&self) {
        //1. action check

        //2. verify validity predicates;
        //2.1 todo: update to verification of blinded vps
        //2.2 todo: add blinding circuit check
        for vp in &self.vps {
            vp.verify()
        }
    }

    fn _process(&self, nftree: &mut MerkleTree<Sha256>, mttree: &mut MerkleTree<Sha256>) {
        self.check();
        for i in &self._created_notes {
            //1. add nf to the nullifier tree
            let nf_hash = serializable_to_array(&i.spent_note_nf);
            nftree.insert(nf_hash);
            nftree.commit();

            //2. add commitments to the note commitment tree
            //todo: add ce to the tree
            let cm_hash = serializable_to_array(&i.commitment());
            mttree.insert(cm_hash);
            mttree.commit();
        }

        //3. recompute rt
        // commit() method recomputes the root. as we only need to recompute it once,
        // should we commit just once after all leaves are added to the tree?
        // or we want to "save" every leaf in case of emergency situation?
        //mttree.commit();
        assert!(self._actions.len() < self._max);
        assert!(self._spent_notes.len() < self._max);
    }
}
