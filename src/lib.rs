use crate::poseidon::{
    POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2, POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4,
    WIDTH_3, WIDTH_5,
};
use ark_bls12_377::Fr as Fr377;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ec::{AffineCurve, TEModelParameters};
use ark_ff::*;
use ark_serialize::CanonicalSerialize;
use circuit::circuit_parameters::CircuitParameters;
use plonk_hashing::poseidon::poseidon::{NativeSpec, Poseidon};
use rs_merkle::{algorithms::Blake2s, Hasher, MerkleTree};
use sha2::{Digest, Sha512};

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
    fn hash_to_field(x: &[u8]) -> Self {
        // that's not a good hash but I don't care
        let mut hasher = Sha512::new();
        hasher.update(x);
        let result = hasher.finalize();
        Self::from_le_bytes_mod_order(&result)
    }
}

impl HashToField for ark_vesta::Fr {}
impl HashToField for ark_vesta::Fq {}
impl HashToField for ark_bls12_377::Fq {}
impl HashToField for ark_bw6_761::Fq {} // this field is 761-bit long so sha512 is not even sufficient here
impl HashToField for ark_ed_on_bls12_377::Fr {}

impl HashToField for Fr377 {
    fn hash_to_field(x: &[u8]) -> Self {
        // poseidon implementation
        // todo what is the domain separator?
        // implementation not working for a large input `x`...

        let elts: Vec<Fr377> = x
            .chunks((Fr377::size_in_bits() - 1) / 8 as usize)
            .map(|elt| Fr377::from_le_bytes_mod_order(elt))
            .collect();

        // TODO: decide the length, support 4 for now.
        assert!(elts.len() <= 4);
        match elts.len() {
            1 => {
                let mut poseidon = Poseidon::<(), NativeSpec<Fr377, WIDTH_3>, WIDTH_3>::new(
                    &mut (),
                    &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
                );
                poseidon.input(elts[0]).unwrap();
                poseidon.input(Fr377::zero()).unwrap();
                poseidon.output_hash(&mut ())
            }
            2 => {
                let mut poseidon = Poseidon::<(), NativeSpec<Fr377, WIDTH_3>, WIDTH_3>::new(
                    &mut (),
                    &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
                );
                poseidon.input(elts[0]).unwrap();
                poseidon.input(elts[1]).unwrap();
                poseidon.output_hash(&mut ())
            }
            3 => {
                let mut poseidon = Poseidon::<(), NativeSpec<Fr377, WIDTH_5>, WIDTH_5>::new(
                    &mut (),
                    &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4,
                );
                poseidon.input(elts[0]).unwrap();
                poseidon.input(elts[1]).unwrap();
                poseidon.input(elts[2]).unwrap();
                poseidon.input(Fr377::zero()).unwrap();
                poseidon.output_hash(&mut ())
            }
            _ => {
                let mut poseidon = Poseidon::<(), NativeSpec<Fr377, WIDTH_5>, WIDTH_5>::new(
                    &mut (),
                    &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY4,
                );
                poseidon.input(elts[0]).unwrap();
                poseidon.input(elts[1]).unwrap();
                poseidon.input(elts[2]).unwrap();
                poseidon.input(elts[3]).unwrap();
                poseidon.output_hash(&mut ())
            }
        }
    }
}

/// Pseudorandom function
fn prf<F: PrimeField + HashToField>(x: &[u8]) -> F {
    F::hash_to_field(x)
}

/// Commitment
/// Binding and hiding
fn com<F: PrimeField + HashToField>(x: &[u8], rand: F) -> F {
    // F is supposed to be CurveBaseField
    let y = rand.into_repr().to_bytes_le();
    let z = [x, &y].concat();
    F::hash_to_field(&z)
}

/// Collision-resistant hash
/// Only binding
// A really bad hash-to-curve
// TODO: the implementation is a bit weird: it does not really depends on CP and could be written with a curve as a parameter (`fn hash_to_curve<E:Curve>`).
fn crh<CP: CircuitParameters>(data: &[u8]) -> TEGroupAffine<CP::InnerCurve> {
    // let scalar = <CP::InnerCurveScalarField>::hash_to_field(data);
    let _scalar = <CP::CurveScalarField>::hash_to_field(data);
    let scalar =
        CP::InnerCurveScalarField::from_le_bytes_mod_order(&_scalar.into_repr().to_bytes_le());
    TEGroupAffine::prime_subgroup_generator().mul(scalar).into()
}

fn serializable_to_vec<F: CanonicalSerialize>(elem: &F) -> Vec<u8> {
    let mut bytes_prep_send = vec![];
    elem.serialize_unchecked(&mut bytes_prep_send).unwrap();
    bytes_prep_send
}

fn add_to_tree<P: TEModelParameters>(elem: &TEGroupAffine<P>, tree: &mut MerkleTree<Blake2s>) {
    let bytes = serializable_to_vec(elem);
    let h = Blake2s::hash(&bytes);
    tree.insert(h);
    tree.commit();
}

#[cfg(test)]
pub mod tests;
