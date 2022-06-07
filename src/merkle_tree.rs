//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//! Use the implementation of MASP
//!
use crate::poseidon::BinaryHasher;
use ark_ff::{BigInteger, PrimeField};
use rand::{Rng, RngCore};
use std::marker::PhantomData;
pub const TAIGA_COMMITMENT_TREE_DEPTH: usize = 32;

/// A path from a position in a particular commitment tree to the root of that tree.
#[derive(Clone, Debug, PartialEq)]
pub struct MerklePath<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> {
    pub auth_path: Vec<(Node<F, BH>, bool)>,
    // TODO: Do we need the position?
    // pub position: u32,
}

impl<F: PrimeField, BH: BinaryHasher<F> + std::clone::Clone> MerklePath<F, BH> {
    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let auth_path = [(); TAIGA_COMMITMENT_TREE_DEPTH].map(|_| (Node::rand(rng), rng.gen()));
        Self::from_path(auth_path.to_vec())
    }
    /// Constructs a Merkle path directly from a path.
    pub fn from_path(auth_path: Vec<(Node<F, BH>, bool)>) -> Self {
        MerklePath { auth_path }
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Node<F, BH>, hasher: &BH) -> Node<F, BH> {
        self.auth_path
            .iter()
            .fold(leaf, |root, (p, leaf_is_on_right)| match leaf_is_on_right {
                false => Node::combine(&root, p, hasher),
                true => Node::combine(p, &root, hasher),
            })
    }

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

    /// Only used in the circuit.
    pub(crate) fn inner(&self) -> F {
        self.repr
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.repr.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        Self::new(F::from_le_bytes_mod_order(bytes))
    }

    fn combine(lhs: &Self, rhs: &Self, hasher: &BH) -> Self {
        Self::new(hasher.hash_two(&lhs.repr, &rhs.repr).unwrap())
    }
}