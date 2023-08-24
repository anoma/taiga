use std::hash::Hash;

use crate::constant::GENERATOR;
use crate::{
    note::NoteCommitment,
    utils::{extract_p, mod_r_p, prf_nf},
};
use borsh::{BorshDeserialize, BorshSerialize};
use halo2_proofs::arithmetic::Field;
use pasta_curves::group::cofactor::CofactorCurveAffine;
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use rand::RngCore;
use subtle::CtOption;

/// The unique nullifier.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct Nullifier(pallas::Base);

/// The NullifierKeyContainer contains the nullifier_key or the nullifier_key commitment
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub enum NullifierKeyContainer {
    // The NullifierKeyContainer::Commitment is the commitment of NullifierKeyContainer::Key `nk_com = Commitment(nk, 0)`
    Commitment(pallas::Base),
    Key(pallas::Base),
}

impl Nullifier {
    // for test
    pub fn new(nf: pallas::Base) -> Self {
        Self(nf)
    }

    // cm is a point
    // $nf =Extract_P([PRF_{nk}(\rho) + \psi \ mod \ q] * K + cm)$
    pub fn derive(
        nk: &NullifierKeyContainer,
        rho: &pallas::Base,
        psi: &pallas::Base,
        cm: &NoteCommitment,
    ) -> Option<Self> {
        match nk {
            NullifierKeyContainer::Commitment(_) => None,
            NullifierKeyContainer::Key(key) => {
                let k = GENERATOR.to_curve();

                let nf = Nullifier(extract_p(
                    &(k * mod_r_p(prf_nf(*key, *rho) + psi) + cm.inner()),
                ));
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
}

impl Default for Nullifier {
    fn default() -> Nullifier {
        Nullifier(pallas::Base::one())
    }
}

impl BorshSerialize for Nullifier {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_repr())?;
        Ok(())
    }
}

impl BorshDeserialize for Nullifier {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        let value = Option::from(pallas::Base::from_repr(repr)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Nullifier not in field")
        })?;
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

    pub fn random_commitment<R: RngCore>(mut rng: R) -> Self {
        NullifierKeyContainer::Commitment(pallas::Base::random(&mut rng))
    }

    /// Creates an NullifierKeyContainer::Key.
    pub fn from_key(key: pallas::Base) -> Self {
        NullifierKeyContainer::Key(key)
    }

    /// Creates a NullifierKeyContainer::Commitment.
    pub fn from_commitment(cm: pallas::Base) -> Self {
        NullifierKeyContainer::Commitment(cm)
    }

    pub fn get_nk(&self) -> Option<pallas::Base> {
        match self {
            NullifierKeyContainer::Key(key) => Some(*key),
            _ => None,
        }
    }

    pub fn get_commitment(&self) -> pallas::Base {
        match self {
            NullifierKeyContainer::Commitment(v) => *v,
            NullifierKeyContainer::Key(key) => {
                // Commitment(nk, zero), use poseidon hash as Commitment.
                prf_nf(*key, pallas::Base::zero())
            }
        }
    }

    pub fn to_commitment(&self) -> Self {
        match self {
            NullifierKeyContainer::Commitment(_) => *self,
            NullifierKeyContainer::Key(_) => {
                NullifierKeyContainer::Commitment(self.get_commitment())
            }
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
        Nullifier::new(pallas::Base::random(&mut rng))
    }

    pub fn random_nullifier_key<R: RngCore>(mut rng: R) -> NullifierKeyContainer {
        NullifierKeyContainer::from_key(pallas::Base::random(&mut rng))
    }

    pub fn random_nullifier_key_commitment<R: RngCore>(mut rng: R) -> NullifierKeyContainer {
        NullifierKeyContainer::from_commitment(pallas::Base::random(&mut rng))
    }
}
