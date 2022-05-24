use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve, TEModelParameters};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand::prelude::ThreadRng;
use sha2::{Digest, Sha256};

pub struct Ciphertext<C: TEModelParameters>(pub TEGroupAffine<C>, [u8; 32]);

pub struct DecryptionKey<C: TEModelParameters> {
    secret: C::ScalarField,
    ek: EncryptionKey<C>,
}

impl<C: TEModelParameters> DecryptionKey<C> {
    pub fn new(rng: &mut ThreadRng) -> Self {
        let secret = C::ScalarField::rand(rng);
        let ek = EncryptionKey(
            TEGroupAffine::<C>::prime_subgroup_generator()
                .mul(secret)
                .into_affine(),
        );
        Self { secret, ek }
    }

    pub fn decrypt_32_bytes(&self, ct: Ciphertext<C>) -> [u8; 32] {
        let mut bytes = vec![];
        (ct.0.mul(self.secret))
            .serialize_unchecked(&mut bytes)
            .unwrap();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut plain = [0u8; 32];
        for i in 0..32 {
            plain[i] = ct.1[i] ^ result[i];
        }
        plain
    }

    pub fn decrypt(&self, ct: Vec<Ciphertext<C>>) -> Vec<u8> {
        let mut plain: Vec<u8> = vec![];
        for cipher in ct {
            let p = self.decrypt_32_bytes(cipher);
            for pp in p {
                plain.push(pp);
            }
        }
        plain
    }

    pub fn encryption_key(&self) -> &EncryptionKey<C> {
        &self.ek
    }
}

pub struct EncryptionKey<C: TEModelParameters>(TEGroupAffine<C>);

impl<C: TEModelParameters> EncryptionKey<C> {
    pub fn encrypt_32_bytes(&self, m: &[u8], rng: &mut ThreadRng) -> Ciphertext<C> {
        assert!(m.len() <= 32);
        let g = TEGroupAffine::<C>::prime_subgroup_generator();
        let r = C::ScalarField::rand(rng);
        let c1 = g.mul(r).into_affine();

        let mut bytes = vec![];
        (self.0.mul(r)).serialize_unchecked(&mut bytes).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut c2 = [0u8; 32];
        for i in 0..m.len() {
            c2[i] = m[i] ^ result[i];
        }
        Ciphertext::<C>(c1, c2)
    }

    pub fn encrypt(&self, m: &[u8], rng: &mut ThreadRng) -> Vec<Ciphertext<C>> {
        let mut m_extend = m.to_vec();
        while m_extend.len() % 32 != 0 {
            m_extend.push(0);
        }
        let mut cipher: Vec<Ciphertext<C>> = vec![];
        for i in 0..m_extend.len() / 32 {
            cipher.push(self.encrypt_32_bytes(&m_extend[i * 32..(i + 1) * 32], rng));
        }
        cipher
    }
}

#[test]
fn test_el_gamal() {
    use ark_pallas::PallasParameters;

    let mut rng = rand::thread_rng();
    let dk = DecryptionKey::<PallasParameters>::new(&mut rng);
    let ek = dk.encryption_key();

    let msg = "JeMAppelleSimon.................".as_bytes();

    let ciph = ek.encrypt(msg, &mut rng);
    let plain = dk.decrypt(ciph);
    // would not work if msg.len() %32 != 0 because there are zeros at the end of the decryption
    assert_eq!(msg, plain);
}
