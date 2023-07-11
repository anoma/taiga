use crate::constant::GENERATOR;
use crate::{
    note::NoteCommitment,
    utils::{extract_p, mod_r_p, prf_nf},
};
use halo2_proofs::arithmetic::Field;
use pasta_curves::group::cofactor::CofactorCurveAffine;
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use rand::RngCore;
use subtle::CtOption;

/// The unique nullifier.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct Nullifier(pallas::Base);

/// The NullifierKey is to derive the Nullifier
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub enum NullifierKey {
    // The closed NullifierKey is the commitment of open NullifierKey: `closed_nk = Com(open_nk, 0)`
    Closed(pallas::Base),
    Open(pallas::Base),
}

impl Nullifier {
    // for test
    pub fn new(nf: pallas::Base) -> Self {
        Self(nf)
    }

    // cm is a point
    // $nf =Extract_P([PRF_{nk}(\rho) + \psi \ mod \ q] * K + cm)$
    pub fn derive(
        nk: &NullifierKey,
        rho: &pallas::Base,
        psi: &pallas::Base,
        cm: &NoteCommitment,
    ) -> Option<Self> {
        match nk {
            NullifierKey::Closed(_) => None,
            NullifierKey::Open(nk) => {
                let k = GENERATOR.to_curve();

                let nf = Nullifier(extract_p(
                    &(k * mod_r_p(prf_nf(*nk, *rho) + psi) + cm.inner()),
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

impl NullifierKey {
    pub fn random<R: RngCore>(mut rng: R) -> Self {
        NullifierKey::Open(pallas::Base::random(&mut rng))
    }

    /// Creates an open NullifierKey.
    pub fn from_open(nk: pallas::Base) -> Self {
        NullifierKey::Open(nk)
    }

    /// Creates a closed NullifierKey.
    pub fn from_closed(x: pallas::Base) -> Self {
        NullifierKey::Closed(x)
    }

    pub fn get_open_nk(&self) -> Option<pallas::Base> {
        match self {
            NullifierKey::Open(nk) => Some(*nk),
            _ => None,
        }
    }

    pub fn get_closed_nk(&self) -> pallas::Base {
        match self {
            NullifierKey::Closed(v) => *v,
            NullifierKey::Open(nk) => {
                // Com(nk, zero), use poseidon hash as Com.
                prf_nf(*nk, pallas::Base::zero())
            }
        }
    }
}

impl Default for NullifierKey {
    fn default() -> NullifierKey {
        let nk = pallas::Base::default();
        NullifierKey::from_open(nk)
    }
}
