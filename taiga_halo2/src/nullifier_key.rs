use crate::utils::{poseidon_hash, prf_nf};
use ff::Field;
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Copy, Debug, Clone)]
pub struct NullifierDerivingKey(pallas::Base);

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

#[derive(Copy, Debug, Clone)]
pub enum NullifierKeyCom {
    Closed(pallas::Base),
    Open(NullifierDerivingKey),
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
