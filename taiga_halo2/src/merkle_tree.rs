use std::hash::{Hash, Hasher};

use crate::merkle_tree::LR::{L, R};
use crate::resource::ResourceCommitment;
use crate::utils::poseidon_hash;
use crate::{constant::TAIGA_COMMITMENT_TREE_DEPTH, resource::Resource};
use ff::PrimeField;
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::distributions::{Distribution, Standard};
use rand::{Rng, RngCore};
#[cfg(feature = "nif")]
use rustler::NifTuple;
use subtle::CtOption;

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// The root of the resource commitment Merkletree.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "nif", derive(NifTuple))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Anchor(pallas::Base);

impl Anchor {
    pub fn inner(&self) -> pallas::Base {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(bytes).map(Anchor)
    }
}

impl From<pallas::Base> for Anchor {
    fn from(anchor: pallas::Base) -> Anchor {
        Anchor(anchor)
    }
}

impl From<Node> for Anchor {
    fn from(node: Node) -> Anchor {
        Anchor(node.0)
    }
}

impl Hash for Anchor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_repr().hash(state);
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Anchor {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_repr())?;
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Anchor {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let value = crate::utils::read_base_field(reader)?;
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash, Default)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LR {
    R,
    #[default]
    L,
}

impl LR {
    pub fn is_left(&self) -> bool {
        match self {
            R => false,
            L => true,
        }
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    pub fn root(&self, leaf: Node) -> Anchor {
        let mut root = leaf;
        for val in self.merkle_path.iter() {
            root = match val.1 {
                R => Node::combine(&root, &val.0),
                L => Node::combine(&val.0, &root),
            }
        }
        root.into()
    }

    /// Returns the input parameters for merkle tree gadget.
    pub fn inner(&self) -> Vec<(pallas::Base, LR)> {
        self.merkle_path
            .iter()
            .map(|(node, b)| (node.inner(), *b))
            .collect()
    }
}

impl Default for MerklePath {
    fn default() -> MerklePath {
        let merkle_path = (0..TAIGA_COMMITMENT_TREE_DEPTH)
            .map(|_| (Node::from(pallas::Base::one()), L))
            .collect();
        Self::from_path(merkle_path)
    }
}

/// A node within the Sapling commitment tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Node(pallas::Base);

impl Node {
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

impl From<pallas::Base> for Node {
    fn from(node: pallas::Base) -> Node {
        Node(node)
    }
}

impl From<&Resource> for Node {
    fn from(resource: &Resource) -> Node {
        Node(resource.commitment().inner())
    }
}

impl From<ResourceCommitment> for Node {
    fn from(cm: ResourceCommitment) -> Node {
        Node(cm.inner())
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
        let value = crate::utils::read_base_field(reader)?;
        Ok(Self(value))
    }
}

impl Hash for Node {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_repr().hash(state);
    }
}
