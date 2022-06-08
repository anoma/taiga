use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt};
use crate::{action::Action, note::Note, CircuitParameters, add_to_tree, serializable_to_vec, serializable_to_array};
use crate::action;
use rs_merkle::{MerkleTree, Hasher, algorithms::Blake2s};
use crate::circuit::validity_predicate::ValidityPredicate;
use plonk_core::proof_system::Verifier;
use crate::el_gamal::Ciphertext;
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
use rand::rngs::ThreadRng;

pub struct Transaction<CP: CircuitParameters> {
    //max: usize, // the maximum number of actions/notes for a transaction
    actions: Vec<Action<CP>>,
    spent_notes: Vec<Note<CP>>,
    created_notes: Vec<(Note<CP>, Vec<Ciphertext<CP::InnerCurve>>)>,
    vps: Vec<ValidityPredicate<CP>>
}

impl<CP: CircuitParameters> Transaction<CP> {

    pub fn new(
        //max: usize,
        actions: Vec<Action<CP>>,
        spent_notes: Vec<Note<CP>>,
        created_notes: Vec<(Note<CP>, Vec<Ciphertext<CP::InnerCurve>>)>,
        vps: Vec<ValidityPredicate<CP>>)
        -> Self {

        Self {
            //max,
            actions,
            spent_notes,
            created_notes,
            vps,
        }
    }

    fn check(&self) {
        //1. action check

        //2. verify validity predicates;
        //2.1 todo: update to verification of blinded vps
        //2.2 todo: add blinding circuit check
        for vp in &self.vps {
            vp.verify()
        }
    }

    pub fn process(&self, NFtree: &mut MerkleTree<Blake2s>, MTtree: &mut MerkleTree<Blake2s>, CM_CE_list: &mut Vec<(TEGroupAffine<CP::InnerCurve>, Vec<Ciphertext<CP::InnerCurve>>)>, rand: &mut ThreadRng ){
        self.check();
        for i in &self.created_notes {
            //1. add nf to the nullifier tree
            add_to_tree(&i.0.spent_note_nf, NFtree);

            //2. add commitments to the note commitment tree
            //todo: add ce to the tree
            add_to_tree(&i.0.commitment(), MTtree);

            CM_CE_list.push((i.0.commitment(), i.1.clone()));
        }

        //3. recompute rt
        // commit() method recomputes the root. as we only need to recompute it once,
        // should we commit just once after all leaves are added to the tree?
        // or we want to "save" every leaf in case of emergency situation?
        //mttree.commit();
        //assert!(self.actions.len() < self._max);
        //assert!(self.spent_notes.len() < self._max);
    }
}
