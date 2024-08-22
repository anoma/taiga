use crate::{
    constant::TAIGA_RESOURCE_TREE_DEPTH,
    merkle_tree::{MerklePath, Node, LR},
    resource::Resource,
};
use pasta_curves::pallas;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceExistenceWitness {
    resource: Resource,
    merkle_path: [(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH],
}

impl ResourceExistenceWitness {
    pub fn get_resource(&self) -> Resource {
        self.resource
    }

    // TODO: fix the depth
    pub fn get_path(&self) -> [(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH] {
        self.merkle_path
    }

    pub fn is_input(&self) -> bool {
        self.merkle_path[0].1.is_left()
    }

    // get input nf or output cm
    pub fn get_identity(&self) -> pallas::Base {
        if self.is_input() {
            self.resource.get_nf().unwrap().inner()
        } else {
            self.resource.commitment().inner()
        }
    }

    pub fn get_root(&self) -> pallas::Base {
        let id = self.get_identity();
        let node = Node::from(id);
        MerklePath::from(self.get_path()).root(node).inner()
    }
}
