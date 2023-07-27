use crate::constant::{
    NOTE_ENCRYPTION_CIPHERTEXT_NUM, NOTE_ENCRYPTION_PLAINTEXT_NUM, POSEIDON_RATE, POSEIDON_WIDTH,
};
use ff::PrimeField;
use group::Curve;
use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::pallas;

#[derive(Debug, Clone)]
pub struct NoteCiphertext([pallas::Base; NOTE_ENCRYPTION_CIPHERTEXT_NUM]);

#[derive(Debug, Clone)]
pub struct NotePlaintext([pallas::Base; NOTE_ENCRYPTION_PLAINTEXT_NUM]);

#[derive(Debug, Clone)]
pub struct SecretKey(pallas::Point);

impl NoteCiphertext {
    pub fn inner(&self) -> &[pallas::Base; NOTE_ENCRYPTION_CIPHERTEXT_NUM] {
        &self.0
    }

    pub fn encrypt(message: &NotePlaintext, secret_key: &SecretKey, nonce: &pallas::Base) -> Self {
        // Init poseidon sponge state
        let mut poseidon_sponge =
            Self::poseidon_sponge_init(message.inner().len(), secret_key, nonce);

        // Encrypt
        let mut cipher = vec![];
        for chunk in message.inner().chunks(POSEIDON_RATE) {
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

        // Add nonce
        cipher.push(*nonce);

        // Compute the MAC
        poseidon::permute::<_, poseidon::P128Pow5T3, POSEIDON_WIDTH, POSEIDON_RATE>(
            &mut poseidon_sponge.state,
            &poseidon_sponge.mds_matrix,
            &poseidon_sponge.round_constants,
        );
        cipher.push(poseidon_sponge.state[0]);
        cipher.into()
    }

    pub fn decrypt(&self, secret_key: &SecretKey) -> Option<Vec<pallas::Base>> {
        let cipher_len = self.0.len();
        let mac = self.0[cipher_len - 1];
        let nonce = self.0[cipher_len - 2];
        // Init poseidon sponge state
        let mut poseidon_sponge = Self::poseidon_sponge_init(cipher_len - 2, secret_key, &nonce);

        // Decrypt
        let mut msg = vec![];
        for chunk in self.0[0..cipher_len - 2].chunks(POSEIDON_RATE) {
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
        if mac != poseidon_sponge.state[0] {
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

impl From<Vec<pallas::Base>> for NoteCiphertext {
    fn from(input_vec: Vec<pallas::Base>) -> Self {
        NoteCiphertext(
            input_vec
                .try_into()
                .expect("public input with incorrect length"),
        )
    }
}

impl NotePlaintext {
    pub fn inner(&self) -> &[pallas::Base; NOTE_ENCRYPTION_PLAINTEXT_NUM] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<pallas::Base> {
        self.0.to_vec()
    }

    pub fn padding(msg: &Vec<pallas::Base>) -> Self {
        let mut plaintext = msg.clone();
        let padding =
            std::iter::repeat(pallas::Base::zero()).take(NOTE_ENCRYPTION_PLAINTEXT_NUM - msg.len());
        plaintext.extend(padding);
        plaintext.into()
    }
}

impl From<Vec<pallas::Base>> for NotePlaintext {
    fn from(input_vec: Vec<pallas::Base>) -> Self {
        NotePlaintext(
            input_vec
                .try_into()
                .expect("public input with incorrect length"),
        )
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
    let plaintext = NotePlaintext::padding(&message.to_vec());
    let nonce = pallas::Base::from_u128(23333u128);

    // Encryption
    let cipher = NoteCiphertext::encrypt(&plaintext, &key, &nonce);

    // Decryption
    let decryption = cipher.decrypt(&key).unwrap();
    assert_eq!(plaintext.to_vec(), decryption);
}
