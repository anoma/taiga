use crate::constant::VP_COMMITMENT_PERSONALIZATION;
use blake2s_simd::Params;
use byteorder::{ByteOrder, LittleEndian};
use ff::PrimeField;
#[cfg(feature = "serde")]
use serde;

#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidityPredicateCommitment([u8; 32]);

impl ValidityPredicateCommitment {
    pub fn commit<F: PrimeField>(vp: &F, rcm: &F) -> Self {
        let hash = Params::new()
            .hash_length(32)
            .personal(VP_COMMITMENT_PERSONALIZATION)
            .to_state()
            .update(vp.to_repr().as_ref())
            .update(rcm.to_repr().as_ref())
            .finalize();
        Self(hash.as_bytes().try_into().unwrap())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_public_inputs<F: PrimeField>(public_inputs: &[F; 2]) -> Self {
        let mut bytes: [u8; 32] = [0; 32];
        bytes[0..16].copy_from_slice(&public_inputs[0].to_repr().as_ref()[0..16]);
        bytes[16..].copy_from_slice(&public_inputs[1].to_repr().as_ref()[0..16]);
        Self(bytes)
    }

    pub fn to_public_inputs<F: PrimeField>(&self) -> [F; 2] {
        let low = F::from_u128(LittleEndian::read_u128(&self.0[0..16]));
        let high = F::from_u128(LittleEndian::read_u128(&self.0[16..]));
        [low, high]
    }
}
