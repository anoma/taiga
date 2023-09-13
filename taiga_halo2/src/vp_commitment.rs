use crate::constant::VP_COMMITMENT_PERSONALIZATION;
use blake2s_simd::Params;
use byteorder::{ByteOrder, LittleEndian};
use ff::PrimeField;
#[cfg(feature = "nif")]
use rustler::{Decoder, Encoder, Env, NifResult, Term};
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

#[cfg(feature = "nif")]
impl Encoder for ValidityPredicateCommitment {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.0.to_vec().encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for ValidityPredicateCommitment {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let val: Vec<u8> = Decoder::decode(term)?;
        let val_array = val
            .try_into()
            .map_err(|_e| rustler::Error::Atom("failure to decode"))?;
        Ok(ValidityPredicateCommitment(val_array))
    }
}
