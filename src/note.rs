use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::nullifier::Nullifier;
use crate::poseidon::{FieldHasher, WIDTH_3, WIDTH_9};
use crate::token::TokenAddress;
use crate::user_address::UserAddress;
use ark_ff::{BigInteger, PrimeField};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, Poseidon},
};
use rand::RngCore;

/// A note
#[derive(Copy, Debug, Clone)]
pub struct Note<CP: CircuitParameters> {
    pub address: UserAddress<CP>,
    pub token: TokenAddress<CP>,
    pub value: u64,
    pub data: CP::CurveScalarField, // for NFT or whatever. TODO: to be decided the value format.
    pub rho: Nullifier<CP>,         // old nullifier
    pub psi: CP::CurveScalarField,  // computed from spent_note_nf using a PRF
    pub rcm: CP::CurveScalarField,
}

/// A commitment to a note.
#[derive(Copy, Debug, Clone)]
pub struct NoteCommitment<CP: CircuitParameters>(CP::CurveScalarField);

impl<CP: CircuitParameters> Note<CP> {
    pub fn new(
        address: UserAddress<CP>,
        token: TokenAddress<CP>,
        value: u64,
        rho: Nullifier<CP>,
        data: CP::CurveScalarField,
        rcm: CP::CurveScalarField,
    ) -> Self {
        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_3>();
        let psi = poseidon_param.native_hash_two(&rho.inner(), &rcm).unwrap();
        Self {
            address,
            token,
            value,
            data,
            rho,
            psi,
            rcm,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        use ark_ff::UniformRand;
        use rand::Rng;

        let address = UserAddress::<CP>::new(rng);
        let token = TokenAddress::<CP>::new(rng);
        let value: u64 = rng.gen();
        let data = CP::CurveScalarField::rand(rng);
        let rho = Nullifier::new(CP::CurveScalarField::rand(rng));
        let rcm = CP::CurveScalarField::rand(rng);

        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_3>();
        let psi = poseidon_param.native_hash_two(&rho.inner(), &rcm).unwrap();
        Self {
            address,
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
    pub fn commitment(&self) -> Result<NoteCommitment<CP>, TaigaError> {
        let address = self.address.opaque_native()?;
        let token = self.token.opaque_native()?;
        let value_filed = CP::CurveScalarField::from(self.value);
        let commit_fields = vec![
            address,
            token,
            value_filed,
            self.data,
            self.rho.inner(),
            self.psi,
            self.rcm,
        ];

        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_9>();
        let mut poseidon = Poseidon::<(), NativeSpec<CP::CurveScalarField, WIDTH_9>, WIDTH_9>::new(
            &mut (),
            &poseidon_param,
        );
        // Default padding zero
        commit_fields.iter().for_each(|f| {
            poseidon.input(*f).unwrap();
        });
        Ok(NoteCommitment(poseidon.output_hash(&mut ())))
    }

    // temporary interface, remove it after adding the Serialize
    pub fn to_bytes(&self) -> Vec<u8> {
        let cm = self.commitment().unwrap();
        cm.to_bytes()
    }
}

impl<CP: CircuitParameters> NoteCommitment<CP> {
    pub fn inner(&self) -> CP::CurveScalarField {
        self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner().into_repr().to_bytes_le()
    }
}
