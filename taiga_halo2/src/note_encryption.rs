use crate::constant::{POSEIDON_RATE, POSEIDON_WIDTH};
use ff::PrimeField;
use group::Curve;
use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::pallas;

#[derive(Debug, Clone)]
pub struct NoteCipher {
    pub cipher: Vec<pallas::Base>,
}

#[derive(Debug, Clone)]
pub struct SecretKey(pallas::Point);

impl NoteCipher {
    pub fn encrypt(message: &[pallas::Base], secret_key: &SecretKey, nonce: &pallas::Base) -> Self {
        // Init poseidon sponge state
        let mut poseidon_sponge = Self::poseidon_sponge_init(message.len(), secret_key, nonce);

        // Encrypt
        let mut cipher = vec![];
        for chunk in message.chunks(POSEIDON_RATE) {
            poseidon::permute::<_, poseidon::P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE>(
                &mut poseidon_sponge.state,
                &poseidon_sponge.mds_matrix,
                &poseidon_sponge.round_constants,
            );
            for (idx, msg_element) in chunk.iter().enumerate() {
                poseidon_sponge.state[idx] += msg_element;
                cipher.push(poseidon_sponge.state[idx]);
            }
        }

        // Compute the MAC
        poseidon::permute::<_, poseidon::P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE>(
            &mut poseidon_sponge.state,
            &poseidon_sponge.mds_matrix,
            &poseidon_sponge.round_constants,
        );
        cipher.push(poseidon_sponge.state[0]);

        Self { cipher }
    }

    pub fn decrypt(
        &self,
        secret_key: &SecretKey,
        nonce: &pallas::Base,
    ) -> Option<Vec<pallas::Base>> {
        // Init poseidon sponge state
        let mut poseidon_sponge =
            Self::poseidon_sponge_init(self.cipher.len() - 1, secret_key, nonce);

        // Decrypt
        let mut msg = vec![];
        for chunk in self.cipher[0..self.cipher.len() - 1].chunks(POSEIDON_RATE) {
            poseidon::permute::<_, poseidon::P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE>(
                &mut poseidon_sponge.state,
                &poseidon_sponge.mds_matrix,
                &poseidon_sponge.round_constants,
            );
            for (idx, cipher_element) in chunk.iter().enumerate() {
                let msg_element = *cipher_element - poseidon_sponge.state[idx];
                msg.push(msg_element);
                poseidon_sponge.state[idx] = *cipher_element;
            }
        }

        // Check MAC
        poseidon::permute::<_, poseidon::P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE>(
            &mut poseidon_sponge.state,
            &poseidon_sponge.mds_matrix,
            &poseidon_sponge.round_constants,
        );
        if *self.cipher.last().unwrap() != poseidon_sponge.state[0] {
            return None;
        }

        Some(msg)
    }

    fn poseidon_sponge_init(
        message_len: usize,
        secret_key: &SecretKey,
        nonce: &pallas::Base,
    ) -> poseidon::Sponge<
        pallas::Base,
        poseidon::P128Pow5T3,
        poseidon::Absorbing<pallas::Base, POSEIDON_RATE>,
        POSEIDON_WIDTH,
        POSEIDON_RATE,
    > {
        let key_coord = secret_key.get_coordinates();
        let length_nonce = nonce
            + pallas::Base::from(message_len as u64) * pallas::Base::from_u128(1 << 64).square();
        let state = [key_coord.0, key_coord.1, length_nonce];
        poseidon::Sponge::<_, poseidon::P128Pow5T3, _, POSEIDON_WIDTH, POSEIDON_RATE>::init(state)
    }
}

impl SecretKey {
    pub fn from_dh_exchange(pk: &pallas::Point, sk: &pallas::Scalar) -> Self {
        Self(pk * sk)
    }

    pub fn inner(&self) -> pallas::Point {
        self.0
    }

    pub fn get_coordinates(&self) -> (pallas::Base, pallas::Base) {
        let coordinates = self.0.to_affine().coordinates().unwrap();
        (*coordinates.x(), *coordinates.y())
    }
}

#[test]
fn test_halo2_note_encryption() {
    use ff::Field;
    use group::Group;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    // Key generation
    let sk = pallas::Scalar::random(&mut rng);
    let pk = pallas::Point::random(&mut rng);

    let key = SecretKey::from_dh_exchange(&pk, &sk);
    let message = [
        pallas::Base::one(),
        pallas::Base::one(),
        pallas::Base::one(),
    ];
    let nonce = pallas::Base::from_u128(23333u128);

    // Encryption
    let cipher = NoteCipher::encrypt(&message, &key, &nonce);

    // Decryption
    let plaintext = cipher.decrypt(&key, &nonce).unwrap();
    assert_eq!(message.to_vec(), plaintext);
}
