use crate::{
    add_to_tree, circuit::circuit_parameters::CircuitParameters, crh, el_gamal::Ciphertext,
    serializable_to_vec, user::User,
};
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ff::BigInteger256;
use ark_serialize::*;
use rand::{prelude::ThreadRng, Rng};
use rs_merkle::{algorithms::Blake2s, MerkleTree};

#[derive(CanonicalSerialize)]
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
        user: &User<CP>,
        token_address: CP::CurveScalarField,
        value: u32,
        spent_note_nf: TEGroupAffine<CP::InnerCurve>,
        psi: CP::InnerCurveScalarField,
        nc_tree: &mut MerkleTree<Blake2s>,
        nc_en_list: &mut Vec<(
            TEGroupAffine<CP::InnerCurve>,
            Vec<Ciphertext<CP::InnerCurve>>,
        )>,
        rng: &mut ThreadRng,
    ) -> Self {
        let note = Self {
            owner_address: user.address(),
            token_address: token_address,
            value: value,
            rcm: rng.gen(),
            data: 0,
            spent_note_nf: spent_note_nf,
            psi: psi,
        };

        let cm = note.commitment();
        add_to_tree(&cm, nc_tree);
        note.add_to_nc_en_list(user, rng, cm, nc_en_list);

        note
    }

    pub fn commitment(&self) -> TEGroupAffine<CP::InnerCurve> {
        // TODO: Consider Sinsemilla hash for this
        //we just concat all of the note fields and multiply the curve
        // generator by it (bad) the fields of a note we should commit
        // to aren't defined in the pbc spec yet also, note commitment
        // should be implemented with Sinsemilla (according to the pbc spec)

        let bytes = serializable_to_vec(self);
        crh::<CP>(&bytes)
    }

    pub fn add_to_nc_en_list(
        &self,
        user: &User<CP>,
        rand: &mut ThreadRng,
        cm: TEGroupAffine<CP::InnerCurve>,
        nc_en_list: &mut Vec<(
            TEGroupAffine<CP::InnerCurve>,
            Vec<Ciphertext<CP::InnerCurve>>,
        )>,
    ) {
        // El Gamal encryption
        let bytes = serializable_to_vec(self);
        let ec = user.enc_key().encrypt(&bytes, rand);
        // update nc_en_list
        nc_en_list.push((cm, ec));
    }

    // SHOULD BE PRIVATE??
    pub fn get_rcm(&self) -> BigInteger256 {
        self.rcm
    }
}
