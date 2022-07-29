use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::nullifier::Nullifier;
use crate::poseidon::{FieldHasher, WIDTH_3, WIDTH_9};
use crate::token::Token;
use crate::user::User;
use ark_ff::{BigInteger, PrimeField};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, Poseidon},
};
use rand::RngCore;
use pasta_curves::vesta;

/// A note
#[derive(Debug, Clone)]
pub struct Note {
    /// Owner of the note
    pub user: User,
    pub token: Token,
    pub value: u64,
    /// for NFT or whatever. TODO: to be decided the value format.
    pub data: vesta::Scalar,
    /// old nullifier. Nonce which is a deterministically computed, unique nonce
    pub rho: Nullifier,
    /// computed from spent_note_nf using a PRF
    pub psi: vesta::Scalar,
    pub rcm: vesta::Scalar,
}

/// A commitment to a note.
#[derive(Copy, Debug, Clone)]
pub struct NoteCommitment(vesta::Scalar);

impl Note {
    pub fn new(
        user: User,
        token: Token,
        value: u64,
        rho: Nullifier,
        data: vesta::Scalar,
        rcm: vesta::Scalar,
    ) -> Self {
  use halo2_gadgets::poseidon::primitives::{Hash, P128Pow5T3, ConstantLength};
        // Init poseidon param.
        let poseidon_param =Hash::<vesta::Scalar, P128Pow5T3, ConstantLength<2>>::init();
     
        let psi = poseidon_param.hash(&[rho.inner(), rcm]).unwrap();
        Self {
            user,
            token,
            value,
            data,
            rho,
            psi,
            rcm,
        }
    }

    pub fn dummy<CP: CircuitParameters>(rng: &mut impl RngCore) -> Self {
        use ark_ff::UniformRand;
        use rand::Rng;
        use halo2_gadgets::poseidon::primitives::{Hash, P128Pow5T3, ConstantLength};


        let user = User::<CP>::new(rng);
        let token = Token::<CP>::new(rng);
        let value: u64 = rng.gen();
        let data = vesta::Scalar::rand(rng);
        let rho = Nullifier::new(vesta::Scalar::rand(rng));
        let rcm = vesta::Scalar::rand(rng);

// Init poseidon param.
let poseidon_param =Hash::<vesta::Scalar, P128Pow5T3, ConstantLength<2>>::init();
        let psi = poseidon_param.hash(&[rho.inner(), rcm]).unwrap();
        Self {
            user,
            token,
            value,
            data,
            rho,
            psi,
            rcm,
        }
    }

    pub fn dummy_from_token(token: Token, rng: &mut impl RngCore) -> Note {
        use ark_ff::UniformRand;
        use rand::Rng;
        use halo2_gadgets::poseidon::primitives::{Hash, P128Pow5T3, ConstantLength};


        let user = User::new(rng);
        let value: u64 = rng.gen();
        let data = vesta::Scalar::rand(rng);
        let rho = Nullifier::new(vesta::Scalar::rand(rng));
        let rcm = vesta::Scalar::rand(rng);

// Init poseidon param.
let poseidon_param =Hash::<vesta::Scalar, P128Pow5T3, ConstantLength<2>>::init();
        let psi = poseidon_param.hash(&[rho.inner(), rcm]).unwrap();
        Self {
            user,
            token,
            value,
            data,
            rho,
            psi,
            rcm,
        }
    }

    pub fn dummy_from_user(user: User, rng: &mut impl RngCore) -> Note {
        use ark_ff::UniformRand;
        use rand::Rng;
        use halo2_gadgets::poseidon::primitives::{Hash, P128Pow5T3, ConstantLength};


        let token = Token::new(rng);
        let value: u64 = rng.gen();
        let data = vesta::Scalar::rand(rng);
        let rho = Nullifier::new(vesta::Scalar::rand(rng));
        let rcm = vesta::Scalar::rand(rng);

// Init poseidon param.
let poseidon_param =Hash::<vesta::Scalar, P128Pow5T3, ConstantLength<2>>::init();
        let psi = poseidon_param.hash(&[rho.inner(), rcm]).unwrap();
        Self {
            user,
            token,
            value,
            data,
            rho,
            psi,
            rcm,
        }
    }

    // To simplify implementation, can we use NoteCommit from VERI-ZEXE(P26 Commitment).
    // Commit(m, r) = CRH(m||r||0), m is a n filed elements vector, CRH is an algebraic hash function(poseidon here).
    // If the Commit can't provide enough hiding security(to be verified, we have the same problem in
    // address commit and vp commit), consider using hash_to_curve(pedersen_hash_to_curve used in sapling
    // or Sinsemilla_hash_to_curve used in Orchard) and adding rcm*fixed_generator, which based on DL assumption.
    pub fn commitment(&self) -> Result<NoteCommitment, TaigaError> {
        use halo2_gadgets::poseidon::primitives::{Hash, P128Pow5T3, ConstantLength};

        let user_address = self.user.address()?;
        let token_address = self.token.address()?;
        let value_filed = vesta::Scalar::from(self.value);

// Init poseidon param.
let poseidon_param =Hash::<vesta::Scalar, P128Pow5T3, ConstantLength<9>>::init();
Ok(NoteCommitment(poseidon_param.hash(& [user_address, token_address, value_filed, self.data, self.rho.inner(), self.psi, self.rcm])))
    }

    // temporary interface, remove it after adding the Serialize
    pub fn to_bytes(&self) -> Vec<u8> {
        let cm = self.commitment().unwrap();
        cm.to_bytes()
    }
}

impl NoteCommitment {
    pub fn inner(&self) -> vesta::Scalar {
        self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner().into_repr().to_bytes_le()
    }
}
