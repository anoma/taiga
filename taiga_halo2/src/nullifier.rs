use std::hash::Hash;

use crate::{
    resource::ResourceCommitment,
    utils::{poseidon_hash_n, prf_nf, read_base_field},
};
use halo2_proofs::arithmetic::Field;
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use rand::RngCore;
#[cfg(feature = "nif")]
use rustler::{NifTaggedEnum, NifTuple};
use subtle::CtOption;

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// The unique nullifier.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifTuple))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Nullifier(pallas::Base);

/// The NullifierKeyContainer contains the nullifier_key or the nullifier_key commitment
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "nif", derive(NifTaggedEnum))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NullifierKeyContainer {
    // The NullifierKeyContainer::PublicKey is the commitment of NullifierKeyContainer::Key `npk = Commitment(nk, 0)`
    PublicKey(pallas::Base),
    Key(pallas::Base),
}

impl Nullifier {
    // nf = poseidon_hash(nk || nonce || \psi || resource_cm), in which resource_cm is a field element
    pub fn derive(
        nk: &NullifierKeyContainer,
        nonce: &pallas::Base,
        psi: &pallas::Base,
        cm: &ResourceCommitment,
    ) -> Option<Self> {
        match nk {
            NullifierKeyContainer::PublicKey(_) => None,
            NullifierKeyContainer::Key(key) => {
                let nf = Nullifier(poseidon_hash_n([*key, *nonce, *psi, cm.inner()]));
                Some(nf)
            }
        }
    }

    pub fn inner(&self) -> pallas::Base {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(bytes).map(Nullifier)
    }

    pub fn random(mut rng: impl RngCore) -> Self {
        Self(pallas::Base::random(&mut rng))
    }
}

impl From<pallas::Base> for Nullifier {
    fn from(cm: pallas::Base) -> Self {
        Nullifier(cm)
    }
}

impl Default for Nullifier {
    fn default() -> Nullifier {
        Nullifier(pallas::Base::one())
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for Nullifier {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_repr())?;
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for Nullifier {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let value = read_base_field(reader)?;
        Ok(Self(value))
    }
}

impl Hash for Nullifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_repr().hash(state);
    }
}

impl NullifierKeyContainer {
    pub fn random_key<R: RngCore>(mut rng: R) -> Self {
        NullifierKeyContainer::Key(pallas::Base::random(&mut rng))
    }

    pub fn random_npk<R: RngCore>(mut rng: R) -> Self {
        NullifierKeyContainer::PublicKey(pallas::Base::random(&mut rng))
    }

    /// Creates an NullifierKeyContainer::Key.
    pub fn from_key(key: pallas::Base) -> Self {
        NullifierKeyContainer::Key(key)
    }

    /// Creates a NullifierKeyContainer::PublicKey.
    pub fn from_npk(cm: pallas::Base) -> Self {
        NullifierKeyContainer::PublicKey(cm)
    }

    pub fn get_nk(&self) -> Option<pallas::Base> {
        match self {
            NullifierKeyContainer::Key(key) => Some(*key),
            _ => None,
        }
    }

    pub fn get_npk(&self) -> pallas::Base {
        match self {
            NullifierKeyContainer::PublicKey(v) => *v,
            NullifierKeyContainer::Key(key) => {
                // Commitment(nk, zero), use poseidon hash as Commitment.
                prf_nf(*key, pallas::Base::zero())
            }
        }
    }

    pub fn to_commitment(&self) -> Self {
        match self {
            NullifierKeyContainer::PublicKey(_) => *self,
            NullifierKeyContainer::Key(_) => NullifierKeyContainer::PublicKey(self.get_npk()),
        }
    }
}

impl Default for NullifierKeyContainer {
    fn default() -> NullifierKeyContainer {
        let key = pallas::Base::default();
        NullifierKeyContainer::from_key(key)
    }
}

#[cfg(test)]
pub mod tests {
    use halo2_proofs::arithmetic::Field;
    use pasta_curves::pallas;
    use rand::RngCore;

    use super::{Nullifier, NullifierKeyContainer};

    pub fn random_nullifier<R: RngCore>(mut rng: R) -> Nullifier {
        Nullifier::from(pallas::Base::random(&mut rng))
    }

    pub fn random_nullifier_key<R: RngCore>(mut rng: R) -> NullifierKeyContainer {
        NullifierKeyContainer::from_key(pallas::Base::random(&mut rng))
    }

    pub fn random_nullifier_key_commitment<R: RngCore>(mut rng: R) -> NullifierKeyContainer {
        NullifierKeyContainer::from_npk(pallas::Base::random(&mut rng))
    }
}
