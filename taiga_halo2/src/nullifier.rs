use crate::constant::NOTE_COMMITMENT_R_GENERATOR;
use crate::{
    note::NoteCommitment,
    user::NullifierDerivingKey,
    utils::{extract_p, mod_r_p},
};
use group::cofactor::CofactorCurveAffine;
use pasta_curves::pallas;

/// The unique nullifier.
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct Nullifier(pallas::Base);

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
}

impl Default for Nullifier {
    fn default() -> Nullifier {
        Nullifier(pallas::Base::one())
    }
}
