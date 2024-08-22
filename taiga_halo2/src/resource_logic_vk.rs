use blake2b_simd::Params as Blake2bParams;
use halo2_proofs::plonk::VerifyingKey;
use pasta_curves::{
    group::ff::{FromUniformBytes, PrimeField},
    pallas, vesta,
};
use std::hash::Hash;

#[derive(Debug, Clone)]
pub enum ResourceLogicVerifyingKey {
    // VK.
    Uncompressed(VerifyingKey<vesta::Affine>),
    // Compress vk into one element.
    Compressed(pallas::Base),
}

impl ResourceLogicVerifyingKey {
    pub fn from_vk(vk: VerifyingKey<vesta::Affine>) -> Self {
        Self::Uncompressed(vk)
    }

    pub fn from_compressed(vk: pallas::Base) -> Self {
        Self::Compressed(vk)
    }

    pub fn get_vk(&self) -> Option<VerifyingKey<vesta::Affine>> {
        match self {
            ResourceLogicVerifyingKey::Uncompressed(vk) => Some(vk.clone()),
            ResourceLogicVerifyingKey::Compressed(_) => None,
        }
    }

    pub fn get_compressed(&self) -> pallas::Base {
        match self {
            ResourceLogicVerifyingKey::Uncompressed(vk) => {
                let mut hasher = Blake2bParams::new()
                    .hash_length(64)
                    .personal(b"Halo2-Verify-Key")
                    .to_state();

                let s = format!("{:?}", vk.pinned());

                hasher.update(&(s.len() as u64).to_le_bytes());
                hasher.update(s.as_bytes());

                // Hash in final Blake2bState
                pallas::Base::from_uniform_bytes(hasher.finalize().as_array())
            }
            ResourceLogicVerifyingKey::Compressed(v) => *v,
        }
    }
}

impl Default for ResourceLogicVerifyingKey {
    fn default() -> ResourceLogicVerifyingKey {
        ResourceLogicVerifyingKey::Compressed(pallas::Base::one())
    }
}

impl Hash for ResourceLogicVerifyingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let compressed = self.get_compressed();
        compressed.to_repr().as_ref().hash(state);
    }
}

impl PartialEq for ResourceLogicVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.get_compressed() == other.get_compressed()
    }
}

impl Eq for ResourceLogicVerifyingKey {}
