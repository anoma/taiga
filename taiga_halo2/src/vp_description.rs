use blake2b_simd::Params as Blake2bParams;
use ff::Field;
use halo2_proofs::plonk::VerifyingKey;
use pasta_curves::arithmetic::FieldExt;
use rand::RngCore;

use crate::circuit::circuit_parameters::CircuitParameters;

// TODO: add vp_param in future.
#[derive(Debug, Clone)]
pub enum ValidityPredicateDescription<CP: CircuitParameters> {
    // VK.
    Uncompressed(VerifyingKey<CP::Curve>),
    // Compress vk into one element.
    Compressed(CP::CurveScalarField),
}

impl<CP: CircuitParameters> ValidityPredicateDescription<CP> {
    // pub fn from_vp<VP>(
    //     vp: &mut VP,
    //     vp_setup: &<CP::CurvePC as PolynomialCommitment<
    //         CP::CurveScalarField,
    //         DensePolynomial<CP::CurveScalarField>,
    //     >>::UniversalParams,
    // ) -> Result<Self, Error>
    // where
    //     VP: ValidityPredicate<CP>,
    // {
    //     let vk = vp.get_desc_vp(vp_setup)?;
    //     Ok(Self::from_vk(&vk))
    // }

    pub fn from_vk(vk: VerifyingKey<CP::Curve>) -> Self {
        Self::Uncompressed(vk)
    }

    pub fn get_vk(&self) -> Option<VerifyingKey<CP::Curve>> {
        match self {
            ValidityPredicateDescription::Uncompressed(vk) => Some(vk.clone()),
            ValidityPredicateDescription::Compressed(_) => None,
        }
    }

    pub fn get_compressed(&self) -> CP::CurveScalarField {
        match self {
            ValidityPredicateDescription::Uncompressed(vk) => {
                let mut hasher = Blake2bParams::new()
                    .hash_length(64)
                    .personal(b"Halo2-Verify-Key")
                    .to_state();

                let s = format!("{:?}", vk.pinned());

                hasher.update(&(s.len() as u64).to_le_bytes());
                hasher.update(s.as_bytes());

                // Hash in final Blake2bState
                CP::CurveScalarField::from_bytes_wide(hasher.finalize().as_array())
            }
            ValidityPredicateDescription::Compressed(v) => *v,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        Self::Compressed(CP::CurveScalarField::random(rng))
    }
}
