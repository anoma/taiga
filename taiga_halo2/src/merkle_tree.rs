//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//!
use crate::utils::poseidon_hash;
use crate::{constant::TAIGA_COMMITMENT_TREE_DEPTH, note::Note};
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::{Rng, RngCore};

use crate::merkle_tree::LR::{L, R};
use rand::distributions::{Distribution, Standard};

#[cfg(feature = "borsh")]
use ff::PrimeField;

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, PartialEq, Eq, Copy, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl Distribution<LR> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> LR {
        if rng.gen_bool(0.5) {
            L
        } else {
            R
        }
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
/// In Orchard merkle tree, they are using MerkleCRH(layer, left, right), where MerkleCRH is a sinsemilla. We are using poseidon_hash(left, right).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl Default for MerklePath {
    fn default() -> MerklePath {
        let merkle_path = (0..TAIGA_COMMITMENT_TREE_DEPTH)
            .map(|_| (Node::new(pallas::Base::one()), L))
            .collect();
        Self::from_path(merkle_path)
    }
}

/// A node within the Sapling commitment tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Node(pallas::Base);

impl Node {
    pub fn new(v: pallas::Base) -> Self {
        Self(v)
    }

    pub fn from_note(n: &Note) -> Self {
        Self(n.commitment().get_x())
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

#[cfg(feature = "borsh")]
impl BorshSerialize for Node {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_repr())?;
        Ok(())
    }
}

#[cfg(feature = "borsh")]
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
