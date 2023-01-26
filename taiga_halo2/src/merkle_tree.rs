//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//!
use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
use crate::utils::poseidon_hash;
use ff::Field;
use pasta_curves::pallas;
use rand::{Rng, RngCore};

use crate::merkle_tree::Parity::{Odd, Even};
use rand::distributions::{Distribution, Standard};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub enum Parity {
    Even,
    Odd
}

pub fn is_even(p: Parity) -> bool {
    match p {
        Even => true,
        Odd => false
    }
}

pub fn is_odd(p: Parity) -> bool {
    match p {
        Even => false,
        Odd => true
    }
}

pub fn parity(i: usize) -> Parity {
    if i % 2 == 0 { Even } else { Odd }
}

impl Distribution<Parity> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Parity {
        let u: usize = rng.gen();
        parity(u)
    }
}

impl<L> Into<Result<Parity, L>> for Parity {
    fn into(self) -> Result<Parity, L> {
        match self {
            Odd => Ok(Odd),
            Even => Ok(Even),
        }
    }
}

impl Default for Parity {
    fn default() -> Self {
        Odd
    }
}

#[derive(Clone)]
pub struct MerkleTreeLeafs {
    leafs: Vec<Node>,
}

impl MerkleTreeLeafs {
    pub fn new(values: Vec<pallas::Base>) -> Self {
        let nodes_vec = values.iter().map(|x| Node::new(*x)).collect::<Vec<_>>();
        Self { leafs: nodes_vec }
    }

    pub fn root(&mut self) -> Node {
        // the list of leafs is extended with copies of elements so that its length is a power of 2.
        let list = &mut self.leafs;
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
}

/// A path from a position in a particular commitment tree to the root of that tree.
/// In Orchard merkle tree, they are using MerkleCRH(layer, left, right), where MerkleCRH is a sinsemilla. We are using poseidon_hash(left, right).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    auth_path: Vec<(Node, Parity)>,
}

impl MerklePath {
    /// Constructs a random dummy merkle path with depth.
    pub fn dummy(rng: &mut impl RngCore, depth: usize) -> Self {
        let auth_path = (0..depth).map(|_| (Node::rand(rng), rng.gen())).collect();
        Self::from_path(auth_path)
    }

    /// Constructs a Merkle path directly from a path.
    pub fn from_path(auth_path: Vec<(Node, Parity)>) -> Self {
        MerklePath { auth_path }
    }

    pub fn find_sibling(leaf_hashes: &[Node], position: usize) -> (usize, Node) {
        let pos = if position % 2 == 0 {
            position + 1
        } else {
            position - 1
        };
        (pos, leaf_hashes[pos])
    }

    fn build_auth_path(leaf_hashes: Vec<Node>, position: usize, path: &mut Vec<(Node, Parity)>) {
        let mut new_leaves = vec![];
        if leaf_hashes.len() > 1 {
            let (sibling_pos, sibling) = Self::find_sibling(&leaf_hashes, position);
            path.push((sibling, parity(sibling_pos)));

            for pair in leaf_hashes.chunks(2) {
                let hash_pair = Node::combine(&pair[0], &pair[1]);

                new_leaves.push(hash_pair);
            }

            Self::build_auth_path(new_leaves, position / 2, path);
        }
    }

    pub fn build_merkle_path(leaf_hashes: &Vec<Node>, position: usize) -> Self {
        let mut auth_path = vec![];
        let completed_leaf_hashes = add_remaining_addresses(leaf_hashes);
        Self::build_auth_path(completed_leaf_hashes, position, &mut auth_path);
        MerklePath { auth_path }
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Node) -> Node {
        let mut root = leaf;
        for val in self.auth_path.iter() {
            root = match val.1 {
                Even => Node::combine(&root, &val.0),
                Odd => Node::combine(&val.0, &root),
            }
        }
        root
    }

    /// Returns the input parameters for merkle tree gadget.
    pub fn get_path(&self) -> Vec<(pallas::Base, Parity)> {
        self.auth_path
            .iter()
            .map(|(node, b)| (node.inner(), *b))
            .collect()
    }
}

fn add_remaining_addresses(addresses: &Vec<Node>) -> Vec<Node> {
    let number_of_elems = addresses.len();
    let next_power_of_two = number_of_elems.next_power_of_two();
    let remaining = next_power_of_two - number_of_elems;
    let slice = &addresses[..remaining];
    let mut added = slice.to_vec();
    let mut new_addresses = addresses.clone();
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

impl Default for MerklePath {
    fn default() -> MerklePath {
        let auth_path = (0..TAIGA_COMMITMENT_TREE_DEPTH)
            .map(|_| (Node::new(pallas::Base::one()), Odd))
            .collect();
        Self::from_path(auth_path)
    }
}
