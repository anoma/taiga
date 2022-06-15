use crate::circuit::validity_predicate::ValidityPredicate;
use crate::el_gamal::EncryptedNote;
use crate::{action::Action, add_to_tree, is_in_tree, note::Note, CircuitParameters};
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use rs_merkle::{algorithms::Blake2s, MerkleTree};

pub struct Transaction<'a, CP: CircuitParameters> {
    //max: usize, // the maximum number of actions/notes for a transaction
    _actions: Vec<Action<CP>>,
    spent_notes: Vec<(Note<CP>, TEGroupAffine<CP::InnerCurve>)>,
    created_notes: Vec<(Note<CP>, EncryptedNote<CP::InnerCurve>)>,
    vps: &'a Vec<ValidityPredicate<CP>>,
}

impl<'a, CP: CircuitParameters> Transaction<'a, CP> {
    pub fn new(
        //max: usize,
        _actions: Vec<Action<CP>>,
        spent_notes: Vec<(Note<CP>, TEGroupAffine<CP::InnerCurve>)>,
        created_notes: Vec<(Note<CP>, EncryptedNote<CP::InnerCurve>)>,
        vps: &'a Vec<ValidityPredicate<CP>>,
    ) -> Self {
        Self {
            //max,
            _actions,
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
        for vp in self.vps {
            vp.verify()
        }
    }

    pub fn process(
        &self,
        nf_tree: &mut MerkleTree<Blake2s>,
        mt_tree: &mut MerkleTree<Blake2s>,
        cm_ce_list: &mut Vec<(TEGroupAffine<CP::InnerCurve>, EncryptedNote<CP::InnerCurve>)>,
    ) {
        self.check();
        for i in &self.spent_notes {
            //1. add nf to the nullifier tree
            if !is_in_tree(&i.1, nf_tree) {
                add_to_tree(&i.1, nf_tree);
            }
        }

        for i in &self.created_notes {
            //2. add commitments to the note commitment tree
            add_to_tree(&i.0.commitment(), mt_tree);

            //3. add (cm, ce) pair to the list
            cm_ce_list.push((i.0.commitment(), i.1.clone()));
        }

        //3. recompute rt
        // commit() method recomputes the root. as we only need to recompute it once,
        // should we commit just once after all leaves are added to the tree?
        // or we want to "save" every leaf in case of emergency situation?
        mt_tree.commit();
        //assert!(self.actions.len() < self._max);
        //assert!(self.spent_notes.len() < self._max);
    }
}
