//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//!
use crate::error::TaigaError;
use crate::poseidon::FieldHasher;
use ark_ff::{BigInteger, PrimeField};
use rand::{Rng, RngCore};
use std::marker::PhantomData;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use crate::poseidon::WIDTH_3;

pub const TAIGA_COMMITMENT_TREE_DEPTH: usize = 32;

#[derive(Clone)]
pub struct MerkleTreeLeafs<F: PrimeField, BH: FieldHasher<F> + std::clone::Clone> {
    leafs: Vec<Node<F, BH>>,
}

impl<F: PrimeField, BH: FieldHasher<F> + std::clone::Clone> MerkleTreeLeafs<F, BH> {
    pub fn new(values: Vec<F>) -> Self {
        let nodes_vec = values
            .iter()
            .map(|x| Node::<F, BH>::new(*x))
            .collect::<Vec<_>>();
        Self { leafs: nodes_vec }
    }

    // todo this is not working yet
    pub fn root(&self, hasher: &BH) -> Node<F, BH> {
        // we suppose self.leafs.len() is a power of 2
        let mut list = self.leafs.clone();
        let mut len = list.len();
        while len > 1 {
            for i in 0..len / 2 {
                list[i] = Node::<F, BH>::new(
                    hasher
                        .native_hash_two(&list[2 * i].repr, &list[2 * i + 1].repr)
                        .unwrap(),
                );
            }
            len /= 2;
        }
        list[0].clone()
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq)]
pub struct MerklePath<F: PrimeField, BH: FieldHasher<F> + std::clone::Clone> {
    auth_path: Vec<(Node<F, BH>, bool)>,
}


pub fn find_sibling<F: PrimeField>(leaf_hashes: &Vec<F>, position: usize) -> (usize, F) {
    if position % 2 == 0 { // if position is even
        let pos = position + 1;
        if leaf_hashes.len() == 1 {
            (1, leaf_hashes[0])
        } else {
            (pos, leaf_hashes[pos])
        }
    } else {
        let pos = position - 1;
        (pos, leaf_hashes[pos])
    }
}


fn build_auth_path<F: PrimeField, BH: FieldHasher<F> + std::clone::Clone>(leaf_hashes: Vec<F>, position: usize, path : &mut Vec<(Node<F, BH>, bool)>) {
    let mut new_leaves = vec![];
    if leaf_hashes.len() > 0 {  
        let (sibling_pos, sibling) = find_sibling(&leaf_hashes, position);
        path.push((Node::new(sibling), sibling_pos % 2 == 0));

        for (i, pair) in leaf_hashes.chunks(2).enumerate() {
            if i != position / 2 {
                let hash_pair = PoseidonConstants::generate::<WIDTH_3>()
                                .native_hash_two(&pair[0], &pair[1])
                                .unwrap();

                new_leaves.push(hash_pair);
            }
        }


        build_auth_path(new_leaves, position / 2, path);
    }
}


impl<F: PrimeField, BH: FieldHasher<F> + std::clone::Clone> MerklePath<F, BH> {
    /// Constructs a random dummy merkle path with depth.
    pub fn dummy(rng: &mut impl RngCore, depth: usize) -> Self {
        let auth_path = (0..depth).map(|_| (Node::rand(rng), rng.gen())).collect();
        Self::from_path(auth_path)
    }

    /// Constructs a Merkle path directly from a path.
    pub fn from_path(auth_path: Vec<(Node<F, BH>, bool)>) -> Self {
        MerklePath { auth_path }
    }



    pub fn build_merkle_path(leaf_hashes: Vec<F>, position: usize) -> Self {
        let mut auth_path = vec![];
        build_auth_path(leaf_hashes, position, &mut auth_path);
        MerklePath {auth_path}
    }
    

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Node<F, BH>, hasher: &BH) -> Result<Node<F, BH>, TaigaError> {
        let mut root = leaf;
        for val in self.auth_path.iter() {
            root = match val.1 {
                false => Node::combine(&root, &val.0, hasher)?,
                true => Node::combine(&val.0, &root, hasher)?,
            }
        }
        Ok(root)
    }

    /// Returns the input parameters for merkle tree gadget.
    pub fn get_path(&self) -> Vec<(F, bool)> {
        self.auth_path
            .iter()
            .map(|(node, b)| (node.inner(), *b))
            .collect()
    }
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node<F: PrimeField, BH: FieldHasher<F>> {
    repr: F,
    _hasher: PhantomData<BH>,
}

impl<F: PrimeField, BH: FieldHasher<F>> Node<F, BH> {
    pub fn new(repr: F) -> Self {
        Node {
            repr,
            _hasher: PhantomData::default(),
        }
    }

    pub fn rand(rng: &mut impl RngCore) -> Self {
        Self::new(F::rand(rng))
    }

    // TODO: add new from commitment
    // pub fn new_from_cm(note: &Note)-> Self {}

    pub(crate) fn inner(&self) -> F {
        self.repr
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.repr.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::new(F::from_le_bytes_mod_order(bytes))
    }

    /// Returns the hash result of left node, right node and the hash function.
    fn combine(lhs: &Self, rhs: &Self, hasher: &BH) -> Result<Self, TaigaError> {
        let hash = hasher.native_hash_two(&lhs.repr, &rhs.repr)?;
        Ok(Self::new(hash))
    }
}
