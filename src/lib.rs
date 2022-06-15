
use crate::poseidon::{
    POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2, POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4,
    WIDTH_3, WIDTH_5,
};
use ark_bls12_377::Fq as Fq377;
use ark_bls12_377::Fr as Fr377;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ec::{AffineCurve, TEModelParameters};
use ark_ff::*;
use ark_serialize::CanonicalSerialize;
use circuit::circuit_parameters::CircuitParameters;
use plonk_hashing::poseidon::poseidon::{NativeSpec, Poseidon};
use poseidon::POSEIDON_HASH_PARAM_BLS12_377_BASE_ARITY2;
use poseidon::POSEIDON_HASH_PARAM_BLS12_377_BASE_ARITY4;
use rs_merkle::{algorithms::Blake2s, Hasher, MerkleTree};

pub mod action;
pub mod circuit;
pub mod el_gamal;
pub mod error;
pub mod merkle_tree;
pub mod note;
pub mod poseidon;
pub mod token;
pub mod transaction;
pub mod user;

pub trait HashToField: PrimeField {
    fn hash2_to_field(x: Self, y: Self) -> Self;
    fn hash4_to_field(x: Self, y: Self, z: Self, t: Self) -> Self;
    fn hash_to_field(x: &[u8]) -> Self;
}

impl HashToField for Fr377 {
    fn hash2_to_field(x: Self, y: Self) -> Self {
        let mut poseidon = Poseidon::<(), NativeSpec<Fr377, WIDTH_3>, WIDTH_3>::new(
            &mut (),
            &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
        );
        poseidon.input(x).unwrap();
        poseidon.input(y).unwrap();
        poseidon.output_hash(&mut ())
    }

    fn hash4_to_field(x: Self, y: Self, z: Self, t: Self) -> Self {
        let mut poseidon = Poseidon::<(), NativeSpec<Fr377, WIDTH_5>, WIDTH_5>::new(
            &mut (),
            &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4,
        );
        poseidon.input(x).unwrap();
        poseidon.input(y).unwrap();
        poseidon.input(z).unwrap();
        poseidon.input(t).unwrap();
        poseidon.output_hash(&mut ())
    }

    fn hash_to_field(x: &[u8]) -> Self {
        // DO NOT USE THIS FUNCTION
        println!("SECURITY WARNING!");
        Self::from_le_bytes_mod_order(&x[0..32])
    }
}

impl HashToField for Fq377 {
    fn hash2_to_field(x: Self, y: Self) -> Self {
        let mut poseidon = Poseidon::<(), NativeSpec<Fq377, WIDTH_3>, WIDTH_3>::new(
            &mut (),
            &POSEIDON_HASH_PARAM_BLS12_377_BASE_ARITY2,
        );
        poseidon.input(x).unwrap();
        poseidon.input(y).unwrap();
        poseidon.output_hash(&mut ())
    }

    fn hash4_to_field(x: Self, y: Self, z: Self, t: Self) -> Self {
        let mut poseidon = Poseidon::<(), NativeSpec<Fq377, WIDTH_5>, WIDTH_5>::new(
            &mut (),
            &POSEIDON_HASH_PARAM_BLS12_377_BASE_ARITY4,
        );
        poseidon.input(x).unwrap();
        poseidon.input(y).unwrap();
        poseidon.input(z).unwrap();
        poseidon.input(t).unwrap();
        poseidon.output_hash(&mut ())
    }

    fn hash_to_field(x: &[u8]) -> Self {
        let h = Blake2s::hash(x);
        Self::from_le_bytes_mod_order(&h)
    }
}

/// Pseudorandom function
fn prf4<F: PrimeField + HashToField>(x: F, y: F, z: F, t: F) -> F {
    F::hash4_to_field(x, y, z, t)
}

/// Commitment
/// Binding and hiding
fn com<F: PrimeField + HashToField>(x: &Vec<F>, rand: F) -> F {
    if x.len() == 1 {
        F::hash2_to_field(x[0], rand)
    } else if x.len() == 2 {
        F::hash4_to_field(x[0], x[1], F::zero(), rand)
    } else if x.len() == 3 {
        F::hash4_to_field(x[0], x[1], x[2], rand)
    } else {
        // if this case occurs we need to think about the Poseidon parameters again!
        assert!(false);
        rand
    }
}

/// Collision-resistant hash
/// Only binding
// A really bad hash-to-curve
// TODO: the implementation is a bit weird: it does not really depends on CP and could be written with a curve as a parameter (`fn hash_to_curve<E:Curve>`).
fn crh<CP: CircuitParameters>(data: &Vec<CP::CurveScalarField>) -> TEGroupAffine<CP::InnerCurve> {
    // let scalar = <CP::InnerCurveScalarField>::hash_to_field(data);
    // TODO: data length is 2 for now but will be larger later
    assert_eq!(data.len(), 2);
    let _scalar = <CP::CurveScalarField>::hash2_to_field(data[0], data[1]);
    let scalar =
        CP::InnerCurveScalarField::from_le_bytes_mod_order(&_scalar.into_repr().to_bytes_le());
    TEGroupAffine::prime_subgroup_generator().mul(scalar).into()
}

fn serializable_to_vec<F: CanonicalSerialize>(elem: &F) -> Vec<u8> {
    let mut bytes_prep_send = vec![];
    elem.serialize_unchecked(&mut bytes_prep_send).unwrap();
    bytes_prep_send
}

fn is_in_tree<P: TEModelParameters>(elem: &TEGroupAffine<P>, tree: &mut MerkleTree<Blake2s>) -> bool {
    if tree.leaves().is_none() {
        return false
    }
    let bytes = serializable_to_vec(elem);
    let h = Blake2s::hash(&bytes);
    tree.leaves().unwrap().contains(&h)
}

fn add_to_tree<P: TEModelParameters>(elem: &TEGroupAffine<P>, tree: &mut MerkleTree<Blake2s>) {
    let bytes = serializable_to_vec(elem);
    let h = Blake2s::hash(&bytes);
    tree.insert(h);
    tree.commit();
}

fn add_bytes_to_tree (bytes: Vec<u8>, tree: &mut MerkleTree<Blake2s>) {
    let h = Blake2s::hash(&bytes);
    tree.insert(h);
    tree.commit();
}

fn to_embedded_field<F1: PrimeField, F2: PrimeField>(x: F1) -> F2 {
    // todo this embedding is probably not secure when we use bls12_377::BaseField \hookrightarrow bls12_377::ScalarField because of the different sizes.
    F2::from_le_bytes_mod_order(&x.into_repr().to_bytes_le())
}

#[cfg(test)]
pub mod tests;
