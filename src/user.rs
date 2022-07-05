use crate::nullifier::Nullifier;
use crate::el_gamal::EncryptedNote;
use crate::user_address::NullifierDerivingKey;
use crate::{
    circuit::circuit_parameters::CircuitParameters,
    circuit::{
        blinding_circuit::{blind_gadget, BlindingCircuit},
        validity_predicate::ValidityPredicate,
    },
    el_gamal::{DecryptionKey, EncryptionKey},
    note::Note,
    serializable_to_vec, to_embedded_field,
};
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::constraint_system::StandardComposer;
use rand::prelude::ThreadRng;

pub struct User<CP: CircuitParameters> {
    name: String, // probably not useful: a user will be identified with his address / his public key(?)
    _dec_key: DecryptionKey<CP::InnerCurve>,
    send_vp: ValidityPredicate<CP>,
    recv_vp: ValidityPredicate<CP>,
    blind_vp: BlindingCircuit<CP>,
    pub rcm_addr: CP::CurveScalarField, // Commitment randomness for deriving address
    nk: NullifierDerivingKey<CP::CurveScalarField>, // the nullifier key
    pub com_send_part: CP::CurveScalarField,
}

impl<CP: CircuitParameters> std::fmt::Display for User<CP> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "User {}", self.name,)
    }
}

impl<CP: CircuitParameters> User<CP> {
    #[allow(clippy::too_many_arguments)]
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
        send_gadget: fn(
            &mut StandardComposer<
                <CP as CircuitParameters>::CurveScalarField,
                <CP as CircuitParameters>::InnerCurve,
            >,
            &[CP::CurveScalarField],
            &[CP::CurveScalarField],
        ),
        send_private_inputs: &[CP::CurveScalarField],
        send_public_inputs: &[CP::CurveScalarField],
        recv_gadget: fn(
            &mut StandardComposer<
                <CP as CircuitParameters>::CurveScalarField,
                <CP as CircuitParameters>::InnerCurve,
            >,
            &[CP::CurveScalarField],
            &[CP::CurveScalarField],
        ),
        recv_private_inputs: &[CP::CurveScalarField],
        recv_public_inputs: &[CP::CurveScalarField],
        rng: &mut ThreadRng,
    ) -> User<CP> {
        // sending proof
        let send_vp = ValidityPredicate::<CP>::new(
            curve_setup,
            send_gadget,
            send_private_inputs,
            send_public_inputs,
            true,
            rng,
        );
        // Receiving proof
        let recv_vp = ValidityPredicate::<CP>::new(
            curve_setup,
            recv_gadget,
            recv_private_inputs,
            recv_public_inputs,
            true,
            rng,
        );
        // blinding proof
        let blind_vp = BlindingCircuit::<CP>::new(outer_curve_setup, blind_gadget::<CP>);

        // nullifier key
        let nk = NullifierDerivingKey::rand(rng);

        // commitment to the send part com_r(com_q(desc_send_vp, 0) || nk, 0)
        let com_send_part = CP::com_r(
            &vec![
                to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(send_vp.pack()),
                nk.inner(),
            ],
            CP::CurveScalarField::zero(),
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
            rcm_addr: CP::CurveScalarField::rand(rng),
            nk,
            com_send_part,
        }
    }

    pub fn enc_key(&self) -> &EncryptionKey<CP::InnerCurve> {
        self._dec_key.encryption_key()
    }

    pub fn send(
        &self,
        spent_notes: &mut [&Note<CP>],
        token_distribution: Vec<(&User<CP>, u32)>,
        rand: &mut ThreadRng,
    ) -> Vec<(Note<CP>, EncryptedNote<CP::InnerCurve>)> {
        let total_sent_value = spent_notes.iter().fold(0, |sum, n| sum + n.value);
        let total_dist_value = token_distribution.iter().fold(0, |sum, x| sum + x.1);
        assert!(total_sent_value >= total_dist_value);

        //todo: fix
        let the_one_and_only_token_address = spent_notes[0].token_address;
        let the_one_and_only_nullifier = Nullifier::<CP>::derive_native(
            &self.get_nk(),
            &spent_notes[0].rho,
            &spent_notes[0].psi,
            &spent_notes[0].commitment(),
        );

        let mut new_notes: Vec<(Note<CP>, EncryptedNote<CP::InnerCurve>)> = vec![];
        for (recipient, value) in token_distribution {
            let psi = CP::CurveScalarField::rand(rand);
            let note = Note::<CP>::new(
                recipient.address(),
                the_one_and_only_token_address,
                value,
                the_one_and_only_nullifier.inner(),
                psi,
                &mut ThreadRng::default(),
            );
            let ec = recipient.encrypt(rand, &note);
            new_notes.push((note, ec));
        }
        new_notes
    }

    pub fn address(&self) -> CP::CurveScalarField {
        // send_cm = Com_r( Com_q(desc_vp_addr_send) || nk ) is a public value
        // recv_part = Com_q(desc_vp_addr_recv)
        let recv_cm = self.recv_vp.pack();

        // address = Com_r(send_part || recv_part, rcm_addr)
        CP::com_r(
            &vec![
                self.com_send_part,
                to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(recv_cm),
            ],
            self.rcm_addr,
        )

        // CP::com_r(
        //     &[
        //         self.com_send_part.into_repr().to_bytes_le(),
        //         recv_cm.into_repr().to_bytes_le(),
        //     ]
        //     .concat(),
        //     self.rcm_addr,
        // )
    }

    pub fn check_proofs(&self) {
        self.send_vp.verify();
        self.recv_vp.verify();
        self.blind_vp.verify();
    }

    pub fn encrypt(&self, rand: &mut ThreadRng, note: &Note<CP>) -> EncryptedNote<CP::InnerCurve> {
        // El Gamal encryption
        let bytes = serializable_to_vec(note);
        self.enc_key().encrypt(&bytes, rand)
    }

    // THESE GETTER SHOULD BE PRIVATE!
    // REMOVE THEM ASAP!
    pub fn get_send_vp(&self) -> &ValidityPredicate<CP> {
        &self.send_vp
    }
    pub fn get_recv_vp(&self) -> &ValidityPredicate<CP> {
        &self.recv_vp
    }
    pub fn get_nk(&self) -> NullifierDerivingKey<CP::CurveScalarField> {
        self.nk
    }
}

#[test]
fn test_user_creation() {
    use crate::circuit::gadgets::trivial::trivial_gadget;
    type CP = crate::circuit::circuit_parameters::PairingCircuitParameters;
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();
    let outer_curve_pp =
        <CP as CircuitParameters>::OuterCurvePC::setup(1 << 4, None, &mut rng).unwrap();

    let _user = User::<CP>::new(
        "Simon",
        &pp,
        &outer_curve_pp,
        DecryptionKey::<<CP as CircuitParameters>::InnerCurve>::new(&mut rng),
        trivial_gadget::<CP>,
        &[],
        &[],
        trivial_gadget::<CP>,
        &[],
        &[],
        &mut rng,
    );
}
