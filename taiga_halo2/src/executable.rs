use crate::{
    error::TransactionError, merkle_tree::Anchor, note::NoteCommitment, nullifier::Nullifier,
    value_commitment::ValueCommitment,
};

// Executable is an unified interface for partial transaction, which is the atomic executable uinit.
pub trait Executable {
    fn execute(&self) -> Result<(), TransactionError>;
    fn get_nullifiers(&self) -> Vec<Nullifier>;
    fn get_output_cms(&self) -> Vec<NoteCommitment>;
    fn get_value_commitments(&self) -> Vec<ValueCommitment>;
    fn get_anchors(&self) -> Vec<Anchor>;
}
