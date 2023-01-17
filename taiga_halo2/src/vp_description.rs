use blake2b_simd::Params as Blake2bParams;
use ff::{Field, PrimeField};
use halo2_proofs::plonk::VerifyingKey;
use pasta_curves::{arithmetic::FieldExt, pallas, vesta};
use rand::RngCore;
use std::hash::Hash;

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
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let compressed = self.get_compressed();
        compressed.to_repr().as_ref().hash(state);
    }
}

impl PartialEq for ValidityPredicateDescription {
    fn eq(&self, other: &Self) -> bool {
        self.get_compressed() == other.get_compressed()
    }
}

#[test]
fn test_vpd_hashing() {
    use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
    use halo2_proofs::plonk;
    use rand::rngs::OsRng;
    use std::{collections::hash_map::DefaultHasher, hash::Hasher};

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    let circuit1 = TrivialValidityPredicateCircuit::dummy(&mut OsRng);
    let circuit2 = TrivialValidityPredicateCircuit::dummy(&mut OsRng);
    let circuit3 = TrivialValidityPredicateCircuit::dummy(&mut OsRng);

    let params1 = halo2_proofs::poly::commitment::Params::new(12);
    let vk1 = plonk::keygen_vk(&params1, &circuit1).unwrap();
    let vpd1 = ValidityPredicateDescription::from_vk(vk1.clone());
    let vk1s = format!("{:?}", vk1.pinned());

    let params2 = halo2_proofs::poly::commitment::Params::new(12);
    let vk2 = plonk::keygen_vk(&params2, &circuit2).unwrap();
    let vpd2 = ValidityPredicateDescription::from_vk(vk2.clone());
    let vk2s = format!("{:?}", vk2.pinned());

    // Same circuit, same param => same key
    assert_eq!(vk1s, vk2s); // check that the keys are actually the same
    assert_eq!(calculate_hash(&vpd1), calculate_hash(&vpd2)); // check that the hashes are the same
    assert_eq!(vpd1, vpd2); // check that the vpd's are equal

    let params3 = halo2_proofs::poly::commitment::Params::new(13); // different param => different key
    let vk3 = plonk::keygen_vk(&params3, &circuit3).unwrap();
    let vpd3 = ValidityPredicateDescription::from_vk(vk3.clone());
    let vk3s = format!("{:?}", vk3.pinned());

    // Same circuit, different param => different key
    assert_ne!(vk1s, vk3s); // check that the keys are actually different
    assert_ne!(calculate_hash(&vpd1), calculate_hash(&vpd3)); // check that the hashes are different
    assert_ne!(vpd1, vpd3); // check that the vpd's are not equal
}
