use crate::halo2::{
    constant::NOTE_COMMITMENT_PERSONALIZATION,
    nullifier::Nullifier,
    token::Token,
    user::User,
    utils::{extract_p, poseidon_hash},
};
use bitvec::{array::BitArray, order::Lsb0};
use core::iter;
use ff::Field;
use group::ff::PrimeFieldBits;
use group::Group;
use halo2_gadgets::sinsemilla::primitives;
use pasta_curves::pallas;
use rand::{Rng, RngCore};

/// A commitment to a note.
#[derive(Copy, Debug, Clone)]
pub struct NoteCommitment(pallas::Point);

impl NoteCommitment {
    pub fn inner(&self) -> pallas::Point {
        self.0
    }
}

/// A note
#[derive(Debug, Clone)]
pub struct Note {
    /// Owner of the note
    pub user: User,
    pub token: Token,
    pub value: u64,
    /// for NFT or whatever. TODO: to be decided the value format.
    pub data: pallas::Base,
    /// old nullifier. Nonce which is a deterministically computed, unique nonce
    pub rho: Nullifier,
    /// computed from spent_note_nf using a PRF
    pub psi: pallas::Base,
    pub rcm: pallas::Scalar,
}

impl Note {
    pub fn new(
        user: User,
        token: Token,
        value: u64,
        rho: Nullifier,
        data: pallas::Base,
        rcm: pallas::Scalar,
    ) -> Self {
        let psi = Self::derive_psi(&rho.inner(), &rcm);
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

    // psi = poseidon_hash(rho, (rcm * generator).x)
    // The psi derivation is different from Orchard, in which psi = blake2b(rho||rcm)
    fn derive_psi(rho: &pallas::Base, rcm: &pallas::Scalar) -> pallas::Base {
        let g_rcm_x = extract_p(&(pallas::Point::generator() * rcm));
        poseidon_hash(*rho, g_rcm_x)
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let user = User::dummy(&mut rng);
        let token = Token::dummy(&mut rng);
        let value: u64 = rng.gen();
        let data = pallas::Base::random(&mut rng);
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = Self::derive_psi(&rho.inner(), &rcm);
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
    pub fn commitment(&self) -> NoteCommitment {
        let user_address = self.user.address();
        let token_address = self.token.address();
        let domain = primitives::CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
        let ret = domain
            .commit(
                iter::empty()
                    .chain(user_address.to_le_bits().iter().by_vals())
                    .chain(token_address.to_le_bits().iter().by_vals())
                    .chain(
                        BitArray::<_, Lsb0>::new(self.value.to_be_bytes())
                            .iter()
                            .by_vals(),
                    )
                    .chain(self.data.to_le_bits().iter().by_vals())
                    .chain(self.rho.inner().to_le_bits().iter().by_vals())
                    .chain(self.psi.to_le_bits().iter().by_vals()),
                &self.rcm,
            )
            .unwrap();
        NoteCommitment(ret)
    }
}
