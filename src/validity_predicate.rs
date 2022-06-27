use crate::circuit::circuit_parameters::CircuitParameters;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use rand::RngCore;

// TODO: hash_vp = com_q(desc_vp), get it from vpblind circuit in future.
// It seems that we only need com_q(desc_vp) integrity constraint in vpblind circuit,
// and we can use hash_vp as private input in action circuit and vp circuit?
#[derive(Copy, Debug, Clone)]
pub struct MockHashVP<CP: CircuitParameters> {
    hash_vp: CP::CurveBaseField,
}

impl<CP: CircuitParameters> MockHashVP<CP> {
    pub fn dummy(rng: &mut impl RngCore) -> Self {
        Self {
            hash_vp: CP::CurveBaseField::rand(rng),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.hash_vp.into_repr().to_bytes_le()
    }

    pub fn to_bits(&self) -> Vec<bool> {
        self.hash_vp.into_repr().to_bits_le()
    }
}
