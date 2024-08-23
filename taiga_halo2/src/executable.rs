use pasta_curves::pallas;

use crate::{
    delta_commitment::DeltaCommitment, error::TransactionError, merkle_tree::Anchor,
    nullifier::Nullifier, resource::ResourceCommitment, resource_tree::ResourceMerkleTreeLeaves,
};

// Executable is an unified interface for partial transaction, which is the atomic executable uinit.
pub trait Executable {
    fn execute(&self) -> Result<(), TransactionError>;
    fn get_nullifiers(&self) -> Vec<Nullifier>;
    fn get_output_cms(&self) -> Vec<ResourceCommitment>;
    fn get_delta_commitments(&self) -> Vec<DeltaCommitment>;
    fn get_anchors(&self) -> Vec<Anchor>;
    fn get_resource_merkle_root(&self) -> pallas::Base {
        let mut leaves = vec![];
        self.get_nullifiers()
            .iter()
            .zip(self.get_output_cms())
            .for_each(|(nf, cm)| {
                leaves.push(nf.inner());
                leaves.push(cm.inner());
            });
        let tree = ResourceMerkleTreeLeaves::new(leaves);
        tree.root()
    }
}
