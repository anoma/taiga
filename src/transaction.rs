use crate::{action::Action, note::Note, CircuitParameters};
use blake2::crypto_mac::Mac;
use plonk::proof_system::Verifier;
pub struct Transaction<CP: CircuitParameters> {
    _max: usize, // the maximum number of actions/notes for a transaction
    _actions: Vec<Action<CP>>,
    _spent_notes: Vec<Note<CP>>,
    _created_notes: Vec<Note<CP>>,
}

impl<CP: CircuitParameters> Transaction<CP> {
    fn _check(&self) {
        // check that a transaction is valid, and create new notes
        // todo
        assert!(self._actions.len() < self._max);
        assert!(self._spent_notes.len() < self._max);
    }
}
