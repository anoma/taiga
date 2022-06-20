//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//!
use crate::error::TaigaError;
use crate::poseidon::BinaryHasher;
use ark_ff::{BigInteger, PrimeField};
use rand::{Rng, RngCore};
use std::marker::PhantomData;
pub const TAIGA_COMMITMENT_TREE_DEPTH: usize = 32;

#[derive(Clone)]
pub struct MerkleTreeLeafs<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> {
    leafs: Vec<Node<F, BH>>,
}

impl<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> MerkleTreeLeafs<F, BH> {
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
pub struct MerklePath<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> {
    auth_path: Vec<(Node<F, BH>, bool)>,
}

impl<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> MerklePath<F, BH> {
    /// Constructs a random dummy merkle path with depth.
    pub fn dummy(rng: &mut impl RngCore, depth: usize) -> Self {
        let auth_path = (0..depth).map(|_| (Node::rand(rng), rng.gen())).collect();
        Self::from_path(auth_path)
    }

    /// Constructs a Merkle path directly from a path.
    pub fn from_path(auth_path: Vec<(Node<F, BH>, bool)>) -> Self {
        MerklePath { auth_path }
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
pub struct Node<F: PrimeField, BH: BinaryHasher<F>> {
    repr: F,
    _hasher: PhantomData<BH>,
}

impl<F: PrimeField, BH: BinaryHasher<F>> Node<F, BH> {
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
