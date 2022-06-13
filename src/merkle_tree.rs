//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//!
use crate::error::TaigaError;
use crate::poseidon::BinaryHasher;
use ark_ff::{BigInteger, PrimeField};
use rand::{Rng, RngCore};
use std::marker::PhantomData;
pub const TAIGA_COMMITMENT_TREE_DEPTH: usize = 32;

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq)]
pub struct MerklePath<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> {
    auth_path: Vec<(Node<F, BH>, bool)>,
}

impl<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> MerklePath<F, BH> {
    /// Constructs a random dummy merkle path with depth of TAIGA_COMMITMENT_TREE_DEPTH.
    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let auth_path = [(); TAIGA_COMMITMENT_TREE_DEPTH].map(|_| (Node::rand(rng), rng.gen()));
        Self::from_path(auth_path.to_vec())
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
#[derive(Clone, Debug, PartialEq)]
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

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        Self::new(F::from_le_bytes_mod_order(bytes))
    }

    /// Returns the hash result of left node, right node and the hash function.
    fn combine(lhs: &Self, rhs: &Self, hasher: &BH) -> Result<Self, TaigaError> {
        let hash = hasher.hash_two(&lhs.repr, &rhs.repr)?;
        Ok(Self::new(hash))
    }
}
