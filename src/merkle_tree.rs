//! Implementation of a Merkle tree of commitments used to prove the existence of notes.
//!
use crate::error::TaigaError;
use crate::poseidon::FieldHasher;
use crate::poseidon::WIDTH_3;
use ark_ff::{BigInteger, PrimeField};
use plonk_hashing::poseidon::constants::PoseidonConstants;
use rand::{Rng, RngCore};
use std::marker::PhantomData;

pub const TAIGA_COMMITMENT_TREE_DEPTH: usize = 32;

#[derive(Clone)]
pub struct MerkleTreeLeafs<F: PrimeField, BH: FieldHasher<F>> {
    leafs: Vec<Node<F, BH>>,
}

impl<F: PrimeField, BH: FieldHasher<F>> MerkleTreeLeafs<F, BH> {
    pub fn new(values: Vec<F>) -> Self {
        let nodes_vec = values
            .iter()
            .map(|x| Node::<F, BH>::new(*x))
            .collect::<Vec<_>>();
        Self { leafs: nodes_vec }
    }

    pub fn root(&mut self, hasher: &BH) -> Node<F, BH> {
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
pub struct MerklePath<F: PrimeField, BH: FieldHasher<F>> {
    auth_path: Vec<(Node<F, BH>, bool)>,
}

impl<F: PrimeField, BH: FieldHasher<F>> MerklePath<F, BH> {
    /// Constructs a random dummy merkle path with depth.
    pub fn dummy(rng: &mut impl RngCore, depth: usize) -> Self {
        let auth_path = (0..depth).map(|_| (Node::rand(rng), rng.gen())).collect();
        Self::from_path(auth_path)
    }

    /// Constructs a Merkle path directly from a path.
    pub fn from_path(auth_path: Vec<(Node<F, BH>, bool)>) -> Self {
        MerklePath { auth_path }
    }

    pub fn find_sibling(leaf_hashes: &[F], position: usize) -> (usize, F) {
        let pos = if position % 2 == 0 {
            position + 1
        } else {
            position - 1
        };
        (pos, leaf_hashes[pos])
    }

    fn build_auth_path(leaf_hashes: Vec<F>, position: usize, path: &mut Vec<(Node<F, BH>, bool)>) {
        let mut new_leaves = vec![];
        if leaf_hashes.len() > 1 {
            let (sibling_pos, sibling) = Self::find_sibling(&leaf_hashes, position);
            path.push((Node::new(sibling), sibling_pos % 2 == 0));

            let hasher = PoseidonConstants::generate::<WIDTH_3>();
            for pair in leaf_hashes.chunks(2) {
                let hash_pair = hasher.native_hash_two(&pair[0], &pair[1]).unwrap();

                new_leaves.push(hash_pair);
            }

            Self::build_auth_path(new_leaves, position / 2, path);
        }
    }

    pub fn build_merkle_path(leaf_hashes: &Vec<F>, position: usize) -> Self {
        let mut auth_path = vec![];
        let completed_leaf_hashes = add_remaining_addresses(&leaf_hashes);
        Self::build_auth_path(completed_leaf_hashes, position, &mut auth_path);
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

fn add_remaining_addresses<F: PrimeField>(addresses: &Vec<F>) -> Vec<F> {
    let number_of_elems = addresses.len();
    let next_power_of_two = number_of_elems.next_power_of_two();
    let remaining = next_power_of_two - number_of_elems;
    let slice = &addresses[..remaining];
    let mut added = slice.to_vec();
    let mut new_addresses = addresses.clone();
    new_addresses.append(&mut added);
    new_addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::merkle_tree::Node;
    use crate::poseidon::FieldHasher;
    use crate::user::User;
    use plonk_hashing::poseidon::constants::PoseidonConstants;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;

    #[test]
    // Test a Merkle tree with 4 leaves
    fn test_auth_path_4() {
        let mut rng = rand::thread_rng();
        // user addresses
        let addresses: Vec<F> = (0..4)
            .map(|_| User::<CP>::new(&mut rng).address().unwrap())
            .collect();

        let position = 1;

        let hasher = PoseidonConstants::generate::<WIDTH_3>();
        let hash_2_3 = hasher
            .native_hash_two(&addresses[2], &addresses[3])
            .unwrap();

        let auth_path = &[
            (Node::<F, PoseidonConstants<_>>::new(addresses[0]), true),
            (Node::<F, PoseidonConstants<_>>::new(hash_2_3), false),
        ];

        let merkle_path = MerklePath::from_path(auth_path.to_vec());

        let merkle_path_2: MerklePath<F, PoseidonConstants<_>> =
            MerklePath::build_merkle_path(&addresses, position);

        assert_eq!(merkle_path, merkle_path_2);
    }

    #[test]
    // Test a Merkle tree with 8 leaves
    fn test_auth_path_8() {
        let mut rng = rand::thread_rng();
        // user addresses
        let addresses: Vec<F> = (0..8)
            .map(|_| User::<CP>::new(&mut rng).address().unwrap())
            .collect();

        let position = 4;

        let hasher = PoseidonConstants::generate::<WIDTH_3>();
        let hash_0_1 = hasher
            .native_hash_two(&addresses[0], &addresses[1])
            .unwrap();
        let hash_2_3 = hasher
            .native_hash_two(&addresses[2], &addresses[3])
            .unwrap();
        let hash_0_1_2_3 = hasher.native_hash_two(&hash_0_1, &hash_2_3).unwrap();
        let hash_6_7 = hasher
            .native_hash_two(&addresses[6], &addresses[7])
            .unwrap();

        let auth_path = &[
            (Node::<F, PoseidonConstants<_>>::new(addresses[5]), false),
            (Node::<F, PoseidonConstants<_>>::new(hash_6_7), false),
            (Node::<F, PoseidonConstants<_>>::new(hash_0_1_2_3), true),
        ];

        let merkle_path = MerklePath::from_path(auth_path.to_vec());

        let merkle_path_2: MerklePath<F, PoseidonConstants<_>> =
            MerklePath::build_merkle_path(&addresses, position);

        assert_eq!(merkle_path, merkle_path_2);
    }

    #[test]
    // Test power of two
    fn test_power_of_two_5() {
        let mut rng = rand::thread_rng();
        // user addresses
        let addresses: Vec<F> = (0..5)
            .map(|_| User::<CP>::new(&mut rng).address().unwrap())
            .collect();

        let pow2_addresses = add_remaining_addresses(&addresses);

        assert_eq!(pow2_addresses.len(), 8);
        assert_eq!(pow2_addresses[5..8], addresses[0..3]);
    }

    #[test]
    fn test_power_of_two_9() {
        let mut rng = rand::thread_rng();
        // user addresses
        let addresses: Vec<F> = (0..9)
            .map(|_| User::<CP>::new(&mut rng).address().unwrap())
            .collect();

        let pow2_addresses = add_remaining_addresses(&addresses);

        assert_eq!(pow2_addresses.len(), 16);
        assert_eq!(pow2_addresses[9..16], addresses[0..7]);
    }

    #[test]
    // Test that a vector with 2^n elements stays the same
    fn test_power_of_two_8() {
        let mut rng = rand::thread_rng();
        // user addresses
        let addresses: Vec<F> = (0..8)
            .map(|_| User::<CP>::new(&mut rng).address().unwrap())
            .collect();

        let pow2_addresses = add_remaining_addresses(&addresses);

        assert_eq!(pow2_addresses, addresses);
    }

    #[test]
    // Test a Merkle tree with 5 leaves (not a power of 2)
    fn test_auth_path_5() {
        let mut rng = rand::thread_rng();
        // user addresses
        let addresses: Vec<F> = (0..5)
            .map(|_| User::<CP>::new(&mut rng).address().unwrap())
            .collect();

        let completed_addresses = add_remaining_addresses(&addresses);

        let position = 4;

        let hasher = PoseidonConstants::generate::<WIDTH_3>();
        let hash_0_1 = hasher
            .native_hash_two(&addresses[0], &completed_addresses[1])
            .unwrap();
        let hash_2_3 = hasher
            .native_hash_two(&addresses[2], &completed_addresses[3])
            .unwrap();
        let hash_0_1_2_3 = hasher.native_hash_two(&hash_0_1, &hash_2_3).unwrap();
        let hash_6_7 = hasher
            .native_hash_two(&completed_addresses[6], &completed_addresses[7])
            .unwrap();

        let auth_path = &[
            (
                Node::<F, PoseidonConstants<_>>::new(completed_addresses[5]),
                false,
            ),
            (Node::<F, PoseidonConstants<_>>::new(hash_6_7), false),
            (Node::<F, PoseidonConstants<_>>::new(hash_0_1_2_3), true),
        ];

        let merkle_path = MerklePath::from_path(auth_path.to_vec());

        let merkle_path_2: MerklePath<F, PoseidonConstants<_>> =
            MerklePath::build_merkle_path(&addresses, position);

        assert_eq!(merkle_path, merkle_path_2);
    }
}
