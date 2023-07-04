use crate::{error::TransactionError, nullifier::Nullifier, value_commitment::ValueCommitment};
use pasta_curves::pallas;

// Executable is an unified interface for partial transaction, which is the atomic executable uinit.
pub trait Executable {
    fn execute(&self) -> Result<(), TransactionError>;
    fn get_nullifiers(&self) -> Vec<Nullifier>;
    fn get_output_cms(&self) -> Vec<pallas::Base>;
    fn get_value_commitments(&self) -> Vec<ValueCommitment>;
    fn get_anchors(&self) -> Vec<pallas::Base>;
}
