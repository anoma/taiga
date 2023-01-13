use blake2b_simd::Params as Blake2bParams;
use ff::Field;
use halo2_proofs::plonk::VerifyingKey;
use pasta_curves::{arithmetic::FieldExt, pallas, vesta};
use rand::RngCore;
use std::hash::{Hash, Hasher};

// TODO: add vp_param in future.
#[derive(Debug, Clone)]
pub enum ValidityPredicateDescription {
    // VK.
    Uncompressed(VerifyingKey<vesta::Affine>),
    // Compress vk into one element.
    Compressed(pallas::Base),
}

impl ValidityPredicateDescription {
    pub fn from_vk(vk: VerifyingKey<vesta::Affine>) -> Self {
        Self::Uncompressed(vk)
    }

    pub fn get_vk(&self) -> Option<VerifyingKey<vesta::Affine>> {
        match self {
            ValidityPredicateDescription::Uncompressed(vk) => Some(vk.clone()),
            ValidityPredicateDescription::Compressed(_) => None,
        }
    }

    pub fn get_compressed(&self) -> pallas::Base {
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
                pallas::Base::from_bytes_wide(hasher.finalize().as_array())
            }
            ValidityPredicateDescription::Compressed(v) => *v,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        Self::Compressed(pallas::Base::random(rng))
    }
}

impl Default for ValidityPredicateDescription {
    fn default() -> ValidityPredicateDescription {
        ValidityPredicateDescription::Compressed(pallas::Base::one())
    }
}

impl Hash for ValidityPredicateDescription {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        match self {
            ValidityPredicateDescription::Compressed(f) => {
                let s = format!("{:?}", f);
                s.hash(hasher);
            }
            ValidityPredicateDescription::Uncompressed(vk) => {
                let s = format!("{:?}", vk.pinned());
                s.hash(hasher);
            }
        }
    }
}
