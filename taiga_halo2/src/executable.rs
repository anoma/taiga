use pasta_curves::pallas;

use crate::{
    delta_commitment::DeltaCommitment, error::TransactionError, merkle_tree::Anchor,
    nullifier::Nullifier, resource::ResourceCommitment,
};

// Executable is an unified interface for partial transaction, which is the atomic executable uinit.
pub trait Executable {
    fn execute(&self) -> Result<(), TransactionError>;
    fn get_nullifiers(&self) -> Vec<Nullifier>;
    fn get_output_cms(&self) -> Vec<ResourceCommitment>;
    fn get_delta_commitments(&self) -> Vec<DeltaCommitment>;
    fn get_anchors(&self) -> Vec<Anchor>;
    fn get_resource_merkle_root(&self) -> pallas::Base;
}
