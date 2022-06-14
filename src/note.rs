use crate::{
    add_to_tree, circuit::circuit_parameters::CircuitParameters, crh, el_gamal::Ciphertext,
    serializable_to_vec, user::User,
};
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ff::BigInteger256;
use ark_serialize::*;
use rand::{prelude::ThreadRng, Rng};
use rs_merkle::{algorithms::Blake2s, Hasher, MerkleTree};
use crate::el_gamal::EncryptionKey;

#[derive(CanonicalSerialize)]
#[derive(derivative::Derivative)]
#[derivative(
Copy(bound = "CP: CircuitParameters"),
Clone(bound = "CP: CircuitParameters"),
)]
pub struct Note<CP: CircuitParameters> {
    // For the curves we consider for 128-bit of security, CurveScalarField,
    // InnerCurveScalarField and InnerCurveBaseField are 32 bytes.
    // Thus, a note is represented in 32 + 32 + 4 + 32 + 4 + 2 * 32 + 32 = 200 bytes???
    pub owner_address: CP::CurveScalarField,
    pub token_address: CP::CurveScalarField,
    pub value: u32,
    rcm: BigInteger256,
    data: u32, // for NFT or whatever, we won't use it in this simple example
    pub spent_note_nf: TEGroupAffine<CP::InnerCurve>, // rho parameter
    /// Note value useful for the nullifier
    pub psi: CP::InnerCurveScalarField, // computed from spent_note_nf using a PRF
}

impl<CP: CircuitParameters> Note<CP> {
    pub fn new(
        owner_address: CP::CurveScalarField,
        token_address: CP::CurveScalarField,
        value: u32,
        spent_note_nf: TEGroupAffine<CP::InnerCurve>,
        psi: CP::InnerCurveScalarField,
        rng: &mut ThreadRng,
    ) -> Self {
        Self {
            owner_address: owner_address,
            token_address: token_address,
            value: value,
            rcm: rng.gen(),
            data: 0,
            spent_note_nf: spent_note_nf,
            psi: psi,
        }
    }

    pub fn commitment(&self) -> TEGroupAffine<CP::InnerCurve> {
        // TODO: Consider Sinsemilla hash for this
        //we just concat all of the note fields and multiply the curve
        // generator by it (bad) the fields of a note we should commit
        // to aren't defined in the pbc spec yet also, note commitment
        // should be implemented with Sinsemilla (according to the pbc spec)
        let vec = vec![self.owner_address, self.token_address];
        crh::<CP>(&vec)

        // let mut bytes = vec![];
        // // TODO use serialize_to_vec but for now, we are restricted to 4 field elements because we use Poseidon for the hash.
        // // In the long term, we will use a hash_to_curve with bytes and not a bounded input size (Pedersen or Blake2?).
        // self.owner_address.serialize_unchecked(&mut bytes).unwrap();
        // self.token_address.serialize_unchecked(&mut bytes).unwrap();
        // crh::<CP>(&bytes)
    }

    // SHOULD BE PRIVATE??
    pub fn get_rcm(&self) -> BigInteger256 {
        self.rcm
    }
}
