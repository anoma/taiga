use crate::circuit::circuit_parameters::CircuitParameters;
use crate::note::NoteCommitment;
use crate::poseidon::{FieldHasher, WIDTH_5, self};
use crate::user::NullifierDerivingKey;
use ark_ff::{BigInteger, PrimeField};
use plonk_hashing::poseidon::constants::PoseidonConstants;

use pasta_curves::vesta;
/// The unique nullifier.
#[derive(Copy, Debug, Clone)]
pub struct Nullifier(vesta::Scalar);

impl Nullifier {
    // for test
    pub fn new(nf: vesta::Scalar) -> Self {
        Self(nf)
    }

    // cm is a point
    // // $nf =Extract_P([PRF_{nk}(\rho) = \psi \ mod \ q] * K + cm)$
    // pub fn derive_native(
    //     nk: &NullifierDerivingKey<vesta::Scalar>,
    //     rho: &vesta::Scalar,
    //     psi: &vesta::Scalar,
    //     cm: &TEGroupAffine<CP::InnerCurve>,
    // ) -> Self {
    //     // Init poseidon param.
    //     let poseidon_param: PoseidonConstants<vesta::Scalar> =
    //         PoseidonConstants::generate::<WIDTH_3>();
    //     let prf_nk_rho = poseidon_param.native_hash_two(&nk.inner(), rho).unwrap();
    //     // This requires vesta::Scalar is smaller than CP::InnerCurveScalarField
    //     let scalar_repr = (prf_nk_rho + psi).into_repr();
    //     let scalar = CP::InnerCurveScalarField::from_le_bytes_mod_order(&scalar_repr.to_bytes_le());

    //     let ret = TEGroupAffine::prime_subgroup_generator()
    //         .mul(scalar)
    //         .into_affine()
    //         + cm;

    //     Nullifier(ret.x)
    // }

    // cm is a scalar
    // nf = CRH(nk, rho, psi, cm)
    pub fn derive_native(
        nk: &NullifierDerivingKey<vesta::Scalar>,
        rho: &Nullifier, // Old nullifier
        psi: &vesta::Scalar,
        cm: &NoteCommitment,
    ) -> Self {
        use halo2_gadgets::poseidon::primitives::{Hash, P128Pow5T3, ConstantLength};
        // Init poseidon param.
        let poseidon_param =Hash::<vesta::Scalar, P128Pow5T3, ConstantLength<3>>::init();
        let scalar_vec = vec![nk.inner(), rho.inner(), *psi, cm.inner()];
        let nf = poseidon_param.hash(&scalar_vec).unwrap();

        Nullifier(nf)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(vesta::Scalar::from_le_bytes_mod_order(bytes))
    }

    pub fn inner(&self) -> vesta::Scalar {
        self.0
    }
}
