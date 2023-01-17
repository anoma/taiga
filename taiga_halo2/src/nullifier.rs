use crate::constant::NOTE_COMMITMENT_R_GENERATOR;
use crate::{
    note::NoteCommitment,
    utils::{extract_p, mod_r_p, poseidon_hash, prf_nf},
};
use ff::{Field, PrimeField};
use group::cofactor::CofactorCurveAffine;
use pasta_curves::pallas;
use rand::RngCore;

/// The unique nullifier.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct Nullifier(pallas::Base);

#[derive(Copy, Debug, Clone)]
pub struct NullifierDerivingKey(pallas::Base);

#[derive(Copy, Debug, Clone)]
pub enum NullifierKeyCom {
    Closed(pallas::Base),
    Open(NullifierDerivingKey),
}

impl Nullifier {
    // for test
    pub fn new(nf: pallas::Base) -> Self {
        Self(nf)
    }

    // cm is a point
    // $nf =Extract_P([PRF_{nk}(\rho) + \psi \ mod \ q] * K + cm)$
    pub fn derive_native(
        nk: &NullifierDerivingKey,
        rho: &pallas::Base,
        psi: &pallas::Base,
        cm: &NoteCommitment,
    ) -> Self {
        // TODO: generate a new generator for nullifier_k
        let k = NOTE_COMMITMENT_R_GENERATOR.to_curve();

        Nullifier(extract_p(
            &(k * mod_r_p(nk.compute_nf(*rho) + psi) + cm.inner()),
        ))
    }

    pub fn inner(&self) -> pallas::Base {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl Default for Nullifier {
    fn default() -> Nullifier {
        Nullifier(pallas::Base::one())
    }
}

impl NullifierDerivingKey {
    pub fn new(nk: pallas::Base) -> Self {
        Self(nk)
    }

    pub fn rand(rng: &mut impl RngCore) -> Self {
        Self(pallas::Base::random(rng))
    }

    pub fn compute_nf(&self, rho: pallas::Base) -> pallas::Base {
        prf_nf(self.0, rho)
    }

    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

impl Default for NullifierDerivingKey {
    fn default() -> NullifierDerivingKey {
        NullifierDerivingKey(pallas::Base::one())
    }
}

impl NullifierKeyCom {
    pub fn rand(rng: &mut impl RngCore) -> Self {
        NullifierKeyCom::Open(NullifierDerivingKey::rand(rng))
    }

    /// Creates an open NullifierKeyCom.
    pub fn from_open(nk: NullifierDerivingKey) -> Self {
        NullifierKeyCom::Open(nk)
    }

    /// Creates a closed NullifierKeyCom.
    pub fn from_closed(x: pallas::Base) -> Self {
        NullifierKeyCom::Closed(x)
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
        match self {
            NullifierKeyCom::Open(nk) => Some(*nk),
            _ => None,
        }
    }

    pub fn get_nk_com(&self) -> pallas::Base {
        match self {
            NullifierKeyCom::Closed(v) => *v,
            NullifierKeyCom::Open(nk) => {
                // Com(nk, zero), use poseidon hash as Com.
                // TODO: use a fixed zero temporarily, we can add a user related key later(like note encryption keys)
                poseidon_hash(nk.inner(), pallas::Base::zero())
            }
        }
    }
}

impl Default for NullifierKeyCom {
    fn default() -> NullifierKeyCom {
        let nk = NullifierDerivingKey::default();
        NullifierKeyCom::from_open(nk)
    }
}
