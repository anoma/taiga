use crate::circuit::circuit_parameters::CircuitParameters;
use crate::poseidon::WIDTH_3;
use ark_ec::{
    twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve, ProjectiveCurve,
};
use ark_ff::{BigInteger, PrimeField};
use blake2b_simd::Params;
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, Poseidon},
};
use rand::RngCore;

const PRF_NK_PERSONALIZATION: &[u8; 12] = b"Taiga_PRF_NK";

/// The nullifier key for note spending.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NullifierDerivingKey<F: PrimeField>(F);

/// The unique nullifier.
pub struct Nullifier<CP: CircuitParameters>(CP::CurveScalarField);

impl<F: PrimeField> NullifierDerivingKey<F> {
    pub fn new(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self::prf_nk(&bytes)
    }

    fn prf_nk(r: &[u8]) -> Self {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PRF_NK_PERSONALIZATION)
            .to_state();
        h.update(r);
        Self::from_bytes(h.finalize().as_bytes())
    }

    pub fn inner(&self) -> F {
        self.0
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(F::from_le_bytes_mod_order(bytes))
    }
}

impl<CP: CircuitParameters> Nullifier<CP> {
    // $nf =Extract_P([PRF_{nk}(\rho) = \psi \ mod \ q] * K + cm)$
    pub fn derive(
        nk: &NullifierDerivingKey<CP::CurveScalarField>,
        rho: &CP::CurveScalarField,
        psi: &CP::CurveScalarField,
        cm: &TEGroupAffine<CP::InnerCurve>,
    ) -> Self {
        // This requires CP::CurveScalarField is smaller than CP::InnerCurveScalarField
        let scalar_bits = (Self::prf_nf(nk, rho) + psi).into_repr().to_bits_be();
        let scalar_bigint =
            <<CP::InnerCurveScalarField as PrimeField>::BigInt as BigInteger>::from_bits_le(
                &scalar_bits,
            );
        let scalar = CP::InnerCurveScalarField::from_repr(scalar_bigint).unwrap();

        let ret = TEGroupAffine::prime_subgroup_generator()
            .mul(scalar)
            .into_affine()
            + cm;

        Nullifier(ret.x)
    }

    // Uses poseidon hash with 2 inputs as prf_nf.
    fn prf_nf(
        nk: &NullifierDerivingKey<CP::CurveScalarField>,
        rho: &CP::CurveScalarField,
    ) -> CP::CurveScalarField {
        let param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_3>();
        let mut poseidon = Poseidon::<(), NativeSpec<CP::CurveScalarField, WIDTH_3>, WIDTH_3>::new(
            &mut (),
            &param,
        );
        poseidon.input(nk.inner()).unwrap();
        poseidon.input(*rho).unwrap();
        poseidon.output_hash(&mut ())
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(CP::CurveScalarField::from_le_bytes_mod_order(bytes))
    }
}
