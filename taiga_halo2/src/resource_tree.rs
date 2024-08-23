use crate::{
    constant::{TAIGA_RESOURCE_TREE_DEPTH, TAIGA_RESOURCE_TREE_LEAVES_NUM},
    merkle_tree::{MerklePath, Node, LR},
    resource::Resource,
    utils::poseidon_hash,
};
use pasta_curves::pallas;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceExistenceWitness {
    resource: Resource,
    merkle_path: [(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMerkleTreeLeaves(Vec<pallas::Base>);

impl ResourceExistenceWitness {
    pub fn new(
        resource: Resource,
        merkle_path: [(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH],
    ) -> Self {
        Self {
            resource,
            merkle_path,
        }
    }

    pub fn get_resource(&self) -> Resource {
        self.resource
    }

    // TODO: fix the depth
    pub fn get_path(&self) -> [(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH] {
        self.merkle_path
    }

    pub fn is_input(&self) -> bool {
        !self.merkle_path[0].1.is_left()
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

impl ResourceMerkleTreeLeaves {
    pub fn new(leaves: Vec<pallas::Base>) -> Self {
        assert!(
            leaves.len() <= TAIGA_RESOURCE_TREE_LEAVES_NUM,
            "The number of leaves exceeds the TAIGA_RESOURCE_TREE_LEAVES_NUM"
        );
        ResourceMerkleTreeLeaves(leaves)
    }

    pub fn insert(&mut self, value: pallas::Base) {
        self.0.push(value)
    }

    pub fn root(&self) -> pallas::Base {
        let mut cur_layer = self.0.clone();
        cur_layer.resize(TAIGA_RESOURCE_TREE_LEAVES_NUM, pallas::Base::zero());
        while cur_layer.len() > 1 {
            cur_layer = cur_layer
                .chunks(2)
                .map(|pair| poseidon_hash(pair[0], pair[1]))
                .collect();
        }
        cur_layer[0]
    }

    // Generate the merkle path for the current leave
    pub fn generate_path(
        &self,
        cur_leave: pallas::Base,
    ) -> Option<[(pallas::Base, LR); TAIGA_RESOURCE_TREE_DEPTH]> {
        let mut cur_layer = self.0.clone();
        cur_layer.resize(TAIGA_RESOURCE_TREE_LEAVES_NUM, pallas::Base::zero());
        if let Some(position) = cur_layer.iter().position(|&v| v == cur_leave) {
            let mut merkle_path = Vec::new();
            fn build_merkle_path_inner(
                cur_layer: Vec<pallas::Base>,
                position: usize,
                path: &mut Vec<(pallas::Base, LR)>,
            ) {
                if cur_layer.len() > 1 {
                    let sibling = {
                        let sibling_lr = LR::from(position % 2 != 0);
                        let sibling_value = match sibling_lr {
                            LR::L => cur_layer[position - 1],
                            LR::R => cur_layer[position + 1],
                        };
                        (sibling_value, sibling_lr)
                    };
                    path.push(sibling);

                    let prev_layer = cur_layer
                        .chunks(2)
                        .map(|pair| poseidon_hash(pair[0], pair[1]))
                        .collect();

                    build_merkle_path_inner(prev_layer, position / 2, path);
                }
            }
            build_merkle_path_inner(cur_layer, position, &mut merkle_path);
            Some(merkle_path.try_into().unwrap())
        } else {
            None
        }
    }
}

#[test]
fn test_resource_merkle_leave() {
    use crate::merkle_tree::{MerklePath, Node};

    let target_leave = pallas::Base::one();
    let resource_merkle_tree =
        ResourceMerkleTreeLeaves::new(vec![pallas::Base::zero(), target_leave]);
    let merkle_path = resource_merkle_tree.generate_path(target_leave).unwrap();

    let mut expected_merkle_path = vec![(pallas::Base::zero(), LR::L)];
    let mut cur_node = pallas::Base::zero();
    (1..TAIGA_RESOURCE_TREE_DEPTH).for_each(|_| {
        cur_node = poseidon_hash(cur_node, cur_node);
        expected_merkle_path.push((cur_node, LR::R));
    });

    assert_eq!(merkle_path.to_vec(), expected_merkle_path);

    let merkle_root = resource_merkle_tree.root();
    let path = MerklePath::from(merkle_path);
    let target_node = Node::from(target_leave);
    let expected_root = path.root(target_node);

    assert_eq!(merkle_root, expected_root.inner());
}
