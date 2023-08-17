//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//!
use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
use crate::utils::poseidon_hash;
use borsh::{BorshDeserialize, BorshSerialize};
use ff::PrimeField;
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::{Rng, RngCore};

use crate::merkle_tree::LR::{L, R};
use rand::distributions::{Distribution, Standard};

#[derive(Clone, Debug, PartialEq, Eq, Copy, Default, BorshSerialize, BorshDeserialize)]
pub enum LR {
    R,
    #[default]
    L,
}

pub fn is_right(p: LR) -> bool {
    match p {
        R => true,
        L => false,
    }
}

pub fn is_left(p: LR) -> bool {
    match p {
        R => false,
        L => true,
    }
}

pub fn lr(i: usize) -> LR {
    if i % 2 == 0 {
        L
    } else {
        R
    }
}

impl Distribution<LR> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> LR {
        let u: usize = rng.gen();
        lr(u)
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MerkleTreeLeaves {
    leaves: Vec<Node>,
}

impl MerkleTreeLeaves {
    pub fn new(values: Vec<pallas::Base>) -> Self {
        let nodes_vec = values.iter().map(|x| Node::new(*x)).collect::<Vec<_>>();
        Self { leaves: nodes_vec }
    }

    pub fn root(&mut self) -> Node {
        // the list of leaves is extended with copies of elements so that its length is a power of 2.
        let list = &mut self.leaves;
        let n = list.len();
        let m = n.next_power_of_two();
        let mut ext = list.clone();
        ext.truncate(m - n);
        list.extend(ext);

        let mut len = list.len();
        while len > 1 {
            for i in 0..len / 2 {
                list[i] = Node::combine(&list[2 * i], &list[2 * i + 1]);
            }
            len /= 2;
        }
        list[0]
    }

    pub fn insert(&mut self, value: pallas::Base) -> Self {
        let leaves = &mut self.leaves;
        leaves.push(Node::new(value));
        Self {
            leaves: leaves.to_vec(),
        }
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
/// In Orchard merkle tree, they are using MerkleCRH(layer, left, right), where MerkleCRH is a sinsemilla. We are using poseidon_hash(left, right).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MerklePath {
    merkle_path: Vec<(Node, LR)>,
}

impl MerklePath {
    /// Constructs a random dummy merkle path with depth. Only used in tests.
    pub fn random(rng: &mut impl RngCore, depth: usize) -> Self {
        let merkle_path = (0..depth).map(|_| (Node::rand(rng), rng.gen())).collect();
        Self::from_path(merkle_path)
    }
    /// Constructs a Merkle path directly from a path.
    pub fn from_path(merkle_path: Vec<(Node, LR)>) -> Self {
        MerklePath { merkle_path }
    }

    pub fn find_sibling(leaf_hashes: &[Node], position: usize) -> (usize, Node) {
        let pos = if position % 2 == 0 {
            position + 1
        } else {
            position - 1
        };
        (pos, leaf_hashes[pos])
    }

    fn build_merkle_path_inner(
        leaf_hashes: Vec<Node>,
        position: usize,
        path: &mut Vec<(Node, LR)>,
    ) {
        let mut new_leaves = vec![];
        if leaf_hashes.len() > 1 {
            let (sibling_pos, sibling) = Self::find_sibling(&leaf_hashes, position);
            path.push((sibling, lr(sibling_pos)));

            for pair in leaf_hashes.chunks(2) {
                let hash_pair = Node::combine(&pair[0], &pair[1]);

                new_leaves.push(hash_pair);
            }

            Self::build_merkle_path_inner(new_leaves, position / 2, path);
        }
    }

    pub fn build_merkle_path(leaf_hashes: &[Node], position: usize) -> Self {
        let mut merkle_path = vec![];
        let completed_leaf_hashes = add_remaining_addresses(leaf_hashes);
        Self::build_merkle_path_inner(completed_leaf_hashes, position, &mut merkle_path);
        MerklePath { merkle_path }
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Node) -> Node {
        let mut root = leaf;
        for val in self.merkle_path.iter() {
            root = match val.1 {
                R => Node::combine(&root, &val.0),
                L => Node::combine(&val.0, &root),
            }
        }
        root
    }

    /// Returns the input parameters for merkle tree gadget.
    pub fn get_path(&self) -> Vec<(pallas::Base, LR)> {
        self.merkle_path
            .iter()
            .map(|(node, b)| (node.inner(), *b))
            .collect()
    }
}

fn add_remaining_addresses(addresses: &[Node]) -> Vec<Node> {
    let number_of_elems = addresses.len();
    let next_power_of_two = number_of_elems.next_power_of_two();
    let remaining = next_power_of_two - number_of_elems;
    let slice = &addresses[..remaining];
    let mut added = slice.to_vec();
    let mut new_addresses = addresses.to_owned();
    new_addresses.append(&mut added);
    new_addresses
}

/// A node within the Sapling commitment tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Node(pallas::Base);

impl Node {
    pub fn new(v: pallas::Base) -> Self {
        Self(v)
    }

    pub fn rand(rng: &mut impl RngCore) -> Self {
        Self(pallas::Base::random(rng))
    }

    pub fn inner(&self) -> pallas::Base {
        self.0
    }

    pub fn combine(left: &Node, right: &Node) -> Node {
        Self(poseidon_hash(left.inner(), right.inner()))
    }
}

impl BorshSerialize for Node {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_repr())?;
        Ok(())
    }
}

impl BorshDeserialize for Node {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        let value = Option::from(pallas::Base::from_repr(repr)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Node value not in field")
        })?;
        Ok(Self(value))
    }
}

impl Default for MerklePath {
    fn default() -> MerklePath {
        let merkle_path = (0..TAIGA_COMMITMENT_TREE_DEPTH)
            .map(|_| (Node::new(pallas::Base::one()), L))
            .collect();
        Self::from_path(merkle_path)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
    use crate::merkle_tree::Node;
    use halo2_gadgets::poseidon::primitives as poseidon;
    use pasta_curves::Fp;

    pub fn random_merkle_path<R: RngCore>(mut rng: R) -> MerklePath {
        MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH)
    }

    #[test]
    // Test a Merkle tree with 4 leaves
    fn test_merkle_path_4() {
        let mut rng = rand::thread_rng();

        let hashes: Vec<Node> = (0..4)
            .map(|_| {
                let poseidon = poseidon::Hash::<
                    _,
                    poseidon::P128Pow5T3,
                    poseidon::ConstantLength<4>,
                    3,
                    2,
                >::init();
                let inputs: Vec<Fp> = (0..4).map(|_| Fp::from(rng.gen::<u64>())).collect();
                let f = poseidon.hash(inputs.try_into().expect("slice with incorrect length"));
                Node::new(f)
            })
            .collect();

        let position = 1;

        let hash_2_3 = poseidon_hash(hashes[2].inner(), hashes[3].inner());

        let merkle_path = &[(Node::new(hashes[0].inner()), L), (Node::new(hash_2_3), R)];

        let merkle_path = MerklePath::from_path(merkle_path.to_vec());

        let merkle_path_2: MerklePath = MerklePath::build_merkle_path(&hashes, position);

        assert_eq!(merkle_path, merkle_path_2);
    }
}
