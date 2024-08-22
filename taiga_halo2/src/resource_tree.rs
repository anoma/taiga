use crate::{merkle_tree::MerklePath, resource::Resource};

pub struct ResourceExistenceWitness {
    resource: Resource,
    merkle_path: MerklePath,
}

impl ResourceExistenceWitness {
    pub fn get_resource(&self) -> Resource {
        self.resource
    }

    // TODO: fix the depth
    pub fn get_path(&self) -> MerklePath {
        self.merkle_path.clone()
    }

    pub fn is_input(&self) -> bool {
        self.merkle_path.inner()[0].1.is_left()
    }
}
