use crate::circuit::circuit_parameters::CircuitParameters;
use crate::note::NoteCommitment;
use crate::poseidon::{FieldHasher, WIDTH_5};
use crate::user::NullifierDerivingKey;
use ark_ff::{BigInteger, PrimeField};
use plonk_hashing::poseidon::constants::PoseidonConstants;

/// The unique nullifier.
#[derive(Copy, Debug, Clone)]
pub struct Nullifier<CP: CircuitParameters>(CP::CurveScalarField);

impl<CP: CircuitParameters> Nullifier<CP> {
    // for test
    pub fn new(nf: CP::CurveScalarField) -> Self {
        Self(nf)
    }

    // cm is a point
    // // $nf =Extract_P([PRF_{nk}(\rho) = \psi \ mod \ q] * K + cm)$
    // pub fn derive_native(
    //     nk: &NullifierDerivingKey<CP::CurveScalarField>,
    //     rho: &CP::CurveScalarField,
    //     psi: &CP::CurveScalarField,
    //     cm: &TEGroupAffine<CP::InnerCurve>,
    // ) -> Self {
    //     // Init poseidon param.
    //     let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
    //         PoseidonConstants::generate::<WIDTH_3>();
    //     let prf_nk_rho = poseidon_param.native_hash_two(&nk.inner(), rho).unwrap();
    //     // This requires CP::CurveScalarField is smaller than CP::InnerCurveScalarField
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
        nk: &NullifierDerivingKey<CP::CurveScalarField>,
        rho: &Nullifier<CP>, // Old nullifier
        psi: &CP::CurveScalarField,
        cm: &NoteCommitment<CP>,
    ) -> Self {
        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_5>();
        let scalar_vec = vec![nk.inner(), rho.inner(), *psi, cm.inner()];
        let nf = poseidon_param.native_hash(&scalar_vec).unwrap();

        Nullifier(nf)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(CP::CurveScalarField::from_le_bytes_mod_order(bytes))
    }

    pub fn inner(&self) -> CP::CurveScalarField {
        self.0
    }
}
