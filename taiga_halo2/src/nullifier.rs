use crate::{
    note::NoteCommitment,
    user::NullifierDerivingKey,
    utils::{extract_p, mod_r_p},
};
use halo2_proofs::arithmetic::CurveExt;
use pasta_curves::pallas;

/// The unique nullifier.
#[derive(Copy, Debug, Clone)]
pub struct Nullifier(pallas::Base);

impl Nullifier {
    // for test
    pub fn new(nf: pallas::Base) -> Self {
        Self(nf)
    }

    // cm is a point
    // // $nf =Extract_P([PRF_{nk}(\rho) = \psi \ mod \ q] * K + cm)$
    pub fn derive_native(
        nk: &NullifierDerivingKey,
        rho: &pallas::Base,
        psi: &pallas::Base,
        cm: &NoteCommitment,
    ) -> Self {
        let k = pallas::Point::hash_to_curve("taiga")(b"K");

        Nullifier(extract_p(
            &(k * mod_r_p(nk.prf_nf(*rho) + psi) + cm.inner()),
        ))
    }

    // cm is a scalar
    // nf = CRH(nk, rho, psi, cm)
    // pub fn derive_native(
    //     nk: &NullifierDerivingKey<CP::CurveScalarField>,
    //     rho: &Nullifier<CP>, // Old nullifier
    //     psi: &CP::CurveScalarField,
    //     cm: &NoteCommitment<CP>,
    // ) -> Self {
    //     // Init poseidon param.
    //     let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
    //         PoseidonConstants::generate::<WIDTH_5>();
    //     let scalar_vec = vec![nk.inner(), rho.inner(), *psi, cm.inner()];
    //     let nf = poseidon_param.native_hash(&scalar_vec).unwrap();

    //     Nullifier(nf)
    // }

    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

impl Default for Nullifier {
    fn default() -> Nullifier {
        Nullifier(pallas::Base::one())
    }
}
