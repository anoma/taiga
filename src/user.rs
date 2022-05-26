use crate::{
    add_to_tree,
    circuit::circuit_parameters::CircuitParameters,
    circuit::{
        blinding_circuit::{blind_gadget, BlindingCircuit},
        validity_predicate::{recv_gadget, send_gadget, ValidityPredicate},
    },
    el_gamal::{Ciphertext, DecryptionKey, EncryptionKey},
    note::Note,
    prf,
};
use ark_ec::{
    twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve, ProjectiveCurve,
};
use ark_ff::{BigInteger, PrimeField};
use ark_ff::{BigInteger256, UniformRand};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use rand::{prelude::ThreadRng, Rng};
use rs_merkle::{algorithms::Blake2s, MerkleTree};

pub struct User<CP: CircuitParameters> {
    name: String, // probably not useful: a user will be identified with his address / his public key(?)
    _dec_key: DecryptionKey<CP::InnerCurve>,
    send_vp: ValidityPredicate<CP>,
    recv_vp: ValidityPredicate<CP>,
    blind_vp: BlindingCircuit<CP>,
    pub rcm_addr: BigInteger256, // Commitment randomness for deriving address
    nk: BigInteger256,           // the nullifier key
    pub com_send_part: CP::CurveScalarField,
}

impl<CP: CircuitParameters> std::fmt::Display for User<CP> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "User {}", self.name,)
    }
}

impl<CP: CircuitParameters> User<CP> {
    pub fn new(
        name: &str,
        curve_setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        outer_curve_setup: &<CP::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::UniversalParams,
        dec_key: DecryptionKey<CP::InnerCurve>,
        rng: &mut ThreadRng,
    ) -> User<CP> {
        // sending proof
        let send_vp = ValidityPredicate::<CP>::new(curve_setup, send_gadget::<CP>, true, rng);
        // Receiving proof
        let recv_vp = ValidityPredicate::<CP>::new(curve_setup, recv_gadget::<CP>, true, rng);
        // blinding proof
        let blind_vp = BlindingCircuit::<CP>::new(outer_curve_setup, blind_gadget::<CP>);

        // nullifier key
        let nk: BigInteger256 = rng.gen();

        // commitment to the send part com_r(com_q(desc_send_vp, 0) || nk, 0)
        let com_send_part = CP::com_r(
            &[
                send_vp.pack().into_repr().to_bytes_le().as_slice(),
                nk.to_bytes_le().as_slice(),
            ]
            .concat(),
            BigInteger256::from(0),
        );

        User {
            name: String::from(name),
            // El Gamal keys
            _dec_key: dec_key,
            // sending proofs/circuits
            send_vp,
            recv_vp,
            blind_vp,
            // random element for address
            rcm_addr: rng.gen(),
            nk,
            com_send_part,
        }
    }

    pub fn compute_nullifier(&self, note: &Note<CP>) -> TEGroupAffine<CP::InnerCurve> {
        let scalar = prf::<CP::InnerCurveScalarField>(
            &[
                note.spent_note_nf.to_string().as_bytes(),
                &self.nk.to_bytes_le(),
            ]
            .concat(),
        ) + note.psi;
        TEGroupAffine::prime_subgroup_generator()
            .mul(scalar)
            .into_affine()
            + note.commitment()
    }

    pub fn enc_key(&self) -> &EncryptionKey<CP::InnerCurve> {
        self._dec_key.encryption_key()
    }

    pub fn send(
        &self,
        notes: &mut Vec<&Note<CP>>,
        token_distribution: Vec<(&User<CP>, u32)>,
        rand: &mut ThreadRng,
        _receiver: &User<CP>,
        nf_tree: &mut MerkleTree<Blake2s>,
        nc_tree: &mut MerkleTree<Blake2s>,
        nc_en_list: &mut Vec<(
            TEGroupAffine<CP::InnerCurve>,
            Vec<Ciphertext<CP::InnerCurve>>,
        )>,
    ) -> Vec<Note<CP>> {
        let total_sent_value = notes.iter().fold(0, |sum, n| sum + n.value);
        let total_dist_value = token_distribution.iter().fold(0, |sum, x| sum + x.1);
        assert!(total_sent_value >= total_dist_value);
        let the_one_and_only_token_address = notes[0].token_address.clone();
        let the_one_and_only_nullifier = self.compute_nullifier(notes[0]);

        for note in notes {
            //Compute the nullifier of the spent note and put it in the nullifier tree
            let nullifier = self.compute_nullifier(note);
            add_to_tree::<CP::InnerCurve>(&nullifier, nf_tree);
        }

        let mut new_notes: Vec<_> = vec![];
        for (recipient, value) in token_distribution {
            let psi = CP::InnerCurveScalarField::rand(rand);
            new_notes.push(Note::<CP>::new(
                &recipient,
                the_one_and_only_token_address,
                value,
                the_one_and_only_nullifier,
                psi,
                nc_tree,
                nc_en_list,
                &mut ThreadRng::default(),
            ));
        }
        new_notes
    }

    pub fn address(&self) -> CP::CurveScalarField {
        // send_cm = Com_r( Com_q(desc_vp_addr_send) || nk ) is a public value
        // recv_part = Com_q(desc_vp_addr_recv)
        let recv_cm = self.recv_vp.pack();

        // address = Com_r(send_part || recv_part, rcm_addr)
        CP::com_r(
            &[
                self.com_send_part.into_repr().to_bytes_le(),
                recv_cm.into_repr().to_bytes_le(),
            ]
            .concat(),
            self.rcm_addr,
        )
    }

    pub fn check_proofs(&self) {
        self.send_vp.verify();
        self.recv_vp.verify();
        self.blind_vp.verify();
    }

    // THESE GETTER SHOULD BE PRIVATE!
    // REMOVE THEM ASAP!
    pub fn get_send_vp(&self) -> &ValidityPredicate<CP> {
        &self.send_vp
    }
    pub fn get_recv_vp(&self) -> &ValidityPredicate<CP> {
        &self.recv_vp
    }
    pub fn get_nk(&self) -> BigInteger256 {
        self.nk
    }
}
