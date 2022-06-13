use crate::circuit::gadgets::gadget::trivial_gadget;
use crate::{circuit::circuit_parameters::CircuitParameters, crh, prf4};
use ark_ec::ProjectiveCurve;
use plonk_core::proof_system::Proof;
use rand::prelude::ThreadRng;
use rs_merkle::algorithms::Blake2s;
use rs_merkle::{Hasher, MerkleProof, MerkleTree};

pub struct Action<CP: CircuitParameters> {
    _proof: Proof<CP::CurveScalarField, CP::CurvePC>,
    _public_input: Vec<CP::CurveScalarField>,
    // ...
}

impl<CP: CircuitParameters> Action<CP> {
    /// Note address integrity: `address = Com_r(Com_r(Com_q(desc_vp_send_addr)||nk) || Com_q(desc_vp_recv_addr), rcm_address)`
    ///
    /// # Arguments
    ///
    /// Private inputs:
    /// * `send_vp_hash` - Com_q(desc_vp_send_addr)
    /// * `recv_vp_hash` - Com_q(desc_vp_recv_addr)
    /// * `note_rcm` - Commitment randomness for deriving note address
    /// * `note_owner_address` - Spent note owner address
    #[allow(dead_code)]
    fn check_spent_note_addr_integrity(
        send_vp_hash: CP::CurveBaseField,
        recv_vp_hash: CP::CurveBaseField,
        note_rcm: CP::CurveScalarField,
        nk: CP::CurveScalarField,
        note_owner_addr: CP::CurveScalarField,
    ) {
        assert_eq!(
            CP::com_r(
                &vec![
                    CP::com_r(
                        &vec![
                            to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(
                                send_vp_hash
                            ),
                            nk
                        ],
                        CP::CurveScalarField::zero()
                    ),
                    to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(recv_vp_hash)
                ],
                note_rcm,
            ),
            note_owner_addr
        );
    }

    /// Note address integrity: `address = Com_r(Com_r(Com_q(desc_vp_send_addr)||nk) || Com_q(desc_vp_recv_addr), rcm_address)`
    ///
    /// # Arguments
    ///
    /// Private inputs:
    /// * `send_vp_com` - Com_r(Com_q(desc_vp_addr_send)||nk)
    /// * `recv_vp_hash` - Com_q(desc_vp_recv_addr)
    /// * `note_rcm` - Randomness for deriving note address
    /// * `note_owner_address` - Spent note owner address
    #[allow(dead_code)]
    fn check_output_note_addr_integrity(
        send_vp_com: CP::CurveScalarField,
        recv_vp_hash: CP::CurveBaseField,
        note_rcm: CP::CurveScalarField,
        note_owner_addr: CP::CurveScalarField,
    ) {
        assert_eq!(
            CP::com_r(
                &vec![
                    send_vp_com,
                    to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(recv_vp_hash)
                ],
                note_rcm,
            ),
            note_owner_addr
        );
    }

    /// Token (type) integrity: `token = Com_r(Com_q(desc_token_vp), rcm_token)`
    ///
    /// # Arguments
    ///
    /// Private inputs:
    /// * `hash_tok_vp` - Com_q(desc_token_vp)
    /// * `token_rcm` - Randomness for deriving note address
    /// * `note_token_addr` - Address of the token in the note
    #[allow(dead_code)]
    fn check_token_integrity(
        hash_tok_vp: CP::CurveBaseField, // Com_q(desc_token_vp)
        token_rcm: CP::CurveScalarField,
        note_token_addr: CP::CurveScalarField,
    ) {
        assert_eq!(
            CP::com_r(
                &vec![to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(hash_tok_vp)],
                token_rcm
            ),
            note_token_addr
        );
    }

    /// Address VP integrity: `address_com_vp = Com(Com_q(desc_vp), rcm_address_com_vp)`
    ///
    /// # Arguments
    ///
    /// Public inputs:
    /// * `com_vp` - Commitment of the VP
    /// Private inputs:
    /// * `com_rcm` - Randomness for deriving commitment of the VP
    /// * `hash_vp` - Com_p(desc_vp)
    #[allow(dead_code)]
    fn check_vp_integrity(
        // public
        com_vp: CP::CurveScalarField,
        // private
        com_rcm: CP::CurveScalarField,
        hash_vp: CP::CurveBaseField,
    ) {
        // this needs to be implemented over:
        //  * `CurveBaseField` for binding with the blinding circuit,
        //  * `CurveScalarField` for binding with the note address.
        assert_eq!(
            com_vp,
            // TODO: Use Blake2s to be efficient on both Fr and Fq
            CP::com_r(
                &vec![to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(hash_vp)],
                com_rcm
            )
        );
    }

    /// Verify that the commitment corresponds to a given note
    ///
    /// # Arguments
    ///
    /// Public inputs:
    /// * `note_cm` - Commitment of the note
    /// Private inputs:
    /// * `note_data` - Contents of the note
    /// * `note_rcm` - Randomness for deriving the commitment of the note
    #[allow(dead_code)]
    fn check_note_commitment_integrity(
        // public
        note_cm: TEGroupAffine<CP::InnerCurve>,
        // private
        note_data: Vec<CP::CurveScalarField>,
        _note_rcm: BigInteger256,
    ) {
        assert_eq!(crh::<CP>(&note_data), note_cm);
    }

    /// Nullifier integrity(input note only): `nf = DeriveNullier_nk(note)`
    ///
    /// # Arguments
    ///
    /// Public inputs:
    /// * `nf` - Spent note nullifier
    /// Private inputs:
    /// * `nk` - Sender nullifier key
    /// * `note` - Spent note
    #[allow(dead_code)]
    fn check_note_nullifier_integrity(
        // public
        nf: TEGroupAffine<CP::InnerCurve>,
        // private
        nk: CP::CurveScalarField,
        note: &Note<CP>,
    ) {
        // this part of the circuit is done over `CurveScalarField` even though
        // it is on `CP::InnerCurveScalarField`. It is then converted
        // into `InnerCurveScalarField` for the second part of the circuit.

        let scalar = to_embedded_field::<CP::CurveScalarField, CP::InnerCurveScalarField>(prf4::<
            CP::CurveScalarField,
        >(
            note.spent_note_nf.x,
            note.spent_note_nf.y,
            nk,
            CP::CurveScalarField::zero(),
        )) + note.psi;
        // this part of the circuit is over `InnerCurveBaseField == CurveScalarField`
        assert_eq!(
            TEGroupAffine::prime_subgroup_generator()
                .mul(scalar)
                .into_affine()
                + note.commitment(),
            nf
        );
    }

    /// Check that note exists in the merkle tree, i.e. note is valid in `rt`
    /// Same as Orchard, there is a path in Merkle tree with root `rt` to a note commitment `cm` that opens to `note`
    /// # Arguments
    ///
    /// Public inputs:
    /// * `nc_tree_root` - Root of the note commitments Merkle tree
    /// * `proof_nc` - Merkle proof required to prove the inclusion of items in a data set.
    /// * `note_cm` - Commitment of the note
    /// Private inputs:
    /// * `note_data` - Contents of the note
    /// * `note_rcm` - Randomness for the note commitment
    /// * `index_note_cm` - Index of the note commitment in the Merkle tree
    #[allow(dead_code)]
    fn check_note_existence(
        // public
        nc_tree_root: [u8; 32],
        proof_nc: MerkleProof<Blake2s>,
        note_cm: TEGroupAffine<CP::InnerCurve>,
        // private
        note_data: Vec<CP::CurveScalarField>,
        _note_rcm: BigInteger256,
        index_note_cm: usize,
    ) {
        // proof check
        let bytes = serializable_to_vec(&note_cm);
        let hash_nc = Blake2s::hash(&bytes);
        assert!(proof_nc.verify(nc_tree_root, &[index_note_cm], &[hash_nc], 2));
        // commitment corresponds to spent_note_commitment
        assert_eq!(crh::<CP>(&note_data), note_cm);
    }

    #[allow(dead_code)]
    fn check_blinding_vp(
        // public
        _com_vp: CP::CurveScalarField,
        _blind_desc_vp: usize, // todo
        // private
        _desc_vp: usize, //todo,
        _com_rcm: BigInteger256,
        _blind_rand: [CP::CurveScalarField; 20],
    ) {
        // check that `blind_desc_vp` is the blinding of `desc_vp` with
        // `blind_rand` and that `desc_vp` commits to `com_vp` (this is fresh commit).
    }
}

//
// this is not the circuit implementation but what should be hard-coded in the Action Circuit.
//
use crate::el_gamal::{Ciphertext, DecryptionKey};
use crate::note::Note;
use crate::token::Token;
use crate::user::User;
use crate::{serializable_to_vec, to_embedded_field};
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
use ark_ff::{BigInteger256, Zero};
use ark_poly_commit::PolynomialCommitment;

/// For spent note
/// `note = (address, token, v, data, ρ, ψ, rcm_note)`:
#[allow(dead_code)]
fn spent_notes_checks<CP: CircuitParameters>(
    sender: &User<CP>,
    token: &Token<CP>,
    spent_note: &Note<CP>,
    output_note: &Note<CP>,
    note_commitments: &mut MerkleTree<Blake2s>,
    rng: &mut ThreadRng,
) {
    // Note is a valid note in `rt`
    // Same as Orchard, there is a path in Merkle tree with root `rt` to a note commitment `cm` that opens to `note`

    // hack for note data because for now we are restricted to few input for the commitment
    // TODO change the hash function and put all the note data inside note_data.
    let note_data = vec![spent_note.owner_address, spent_note.token_address];
    Action::<CP>::check_note_existence(
        note_commitments.root().unwrap(),
        note_commitments.proof(&[0]),
        spent_note.commitment(),
        note_data,
        spent_note.get_rcm(),
        0,
    );
    // `address` and `address_com_vp` opens to the same `desc_address_vp`
    // Note address integrity: `address = Com_r(Com_r(Com_q(desc_vp_addr_send)||nk) || Com_q(desc_vp_addr_recv), rcm_address)`
    Action::<CP>::check_spent_note_addr_integrity(
        sender.get_send_vp().pack(),
        sender.get_recv_vp().pack(),
        sender.rcm_addr,
        sender.get_nk(),
        spent_note.owner_address,
    );

    // Address VP integrity for input note: `address_com_vp = Com(Com_q(desc_vp_addr_send), rcm_address_com_vp)`
    let (cm_send_alice, rand_alice) = sender.get_send_vp().fresh_commitment(rng);
    Action::<CP>::check_vp_integrity(cm_send_alice, rand_alice, sender.get_send_vp().pack());

    // Nullifier integrity(input note only): `nf = DeriveNullier_nk(note)`
    Action::<CP>::check_note_nullifier_integrity(
        output_note.spent_note_nf, // nullifier of old note is stored in output_note.spent_note_nf
        sender.get_nk(),
        spent_note,
    );

    // `token` and `token_com_vp` opens to the same `desc_token_vp`
    // Token (type) integrity: `token = Com_r(Com_q(desc_token_vp), rcm_token)`
    Action::<CP>::check_token_integrity(
        token.get_vp().pack(),
        token.rcm_addr,
        spent_note.token_address,
    );

    // Token VP integrity: `com_vp = Com(Com_q(desc_vp_token), rcm_token_com_vp)`
    let (cm_token, rand_token) = token.get_vp().fresh_commitment(rng);
    Action::<CP>::check_vp_integrity(cm_token, rand_token, token.get_vp().pack());
}

/// For output note
/// `note = (address, token, v, data, ρ, ψ, rcm_note)`:
#[allow(dead_code)]
fn output_notes_checks<CP: CircuitParameters>(
    _sender: &User<CP>,
    receiver: &User<CP>,
    token: &Token<CP>,
    output_note: &Note<CP>,
    rng: &mut ThreadRng,
) {
    // `address` and `address_com_vp` opens to the same `desc_address_vp`
    // Note address integrity: `address = Com_r(Com_r(Com_q(desc_vp_addr_send)||nk) || Com_q(desc_vp_addr_recv), rcm_address)`
    Action::<CP>::check_output_note_addr_integrity(
        receiver.com_send_part,
        receiver.get_recv_vp().pack(),
        receiver.rcm_addr,
        output_note.owner_address,
    );

    // Address VP integrity for output note: `address_com_vp = Com(Com_q(desc_vp_addr_recv), rcm_address_com_vp)`
    let (cm_recv_bob, rand_bob) = receiver.get_recv_vp().fresh_commitment(rng);
    Action::<CP>::check_vp_integrity(cm_recv_bob, rand_bob, receiver.get_send_vp().pack());
    // Commitment integrity(output note only): `cm = NoteCom(note, rcm_note)`
    // hack for note data because for now we are restricted to few input for the commitment
    // TODO change the hash function and put all the note data inside note_data.
    let output_note_data = vec![output_note.owner_address, output_note.token_address];
    Action::<CP>::check_note_commitment_integrity(
        output_note.commitment(),
        output_note_data,
        output_note.get_rcm(),
    );

    // `token` and `token_com_vp` opens to the same `desc_token_vp`
    // Token (type) integrity: `token = Com_r(Com_q(desc_token_vp), rcm_token)`
    Action::<CP>::check_token_integrity(
        token.get_vp().pack(),
        token.rcm_addr,
        output_note.token_address,
    );
    // Token VP integrity: `com_vp = Com(Com_q(desc_vp_token), rcm_token_com_vp)`
    let (cm_token, rand_token) = token.get_vp().fresh_commitment(rng);
    Action::<CP>::check_vp_integrity(cm_token, rand_token, token.get_vp().pack());
}

fn _action_checks<CP: CircuitParameters>() {
    let mut rng = rand::thread_rng();

    let pp = CP::CurvePC::setup(1 << 4, None, &mut rng).unwrap();
    let outer_curve_pp = CP::OuterCurvePC::setup(1 << 4, None, &mut rng).unwrap();

    let alice = User::<CP>::new(
        "alice",
        &pp,
        &outer_curve_pp,
        DecryptionKey::<CP::InnerCurve>::new(&mut rng),
        trivial_gadget::<CP>,
        &vec![],
        &vec![],
        trivial_gadget::<CP>,
        &vec![],
        &vec![],
        &mut rng,
    );

    let bob = User::<CP>::new(
        "bob",
        &pp,
        &outer_curve_pp,
        DecryptionKey::<CP::InnerCurve>::new(&mut rng),
        trivial_gadget::<CP>,
        &vec![],
        &vec![],
        trivial_gadget::<CP>,
        &vec![],
        &vec![],
        &mut rng,
    );

    let xan = Token::<CP>::new("xan", &pp, trivial_gadget::<CP>, &mut rng);

    // Creation of a nullifiers tree
    let mut nullifier_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    // Creation of a note commitments tree
    let mut note_commitments = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    // Creation of the {note commitment + encrypted note} list
    let mut nc_en_list: Vec<(
        TEGroupAffine<CP::InnerCurve>,
        Vec<Ciphertext<CP::InnerCurve>>,
    )> = vec![];

    // Creation of a note of 1XAN for Alice
    let spent_note = Note::<CP>::new(
        &alice,
        xan.address(),
        1,
        TEGroupAffine::prime_subgroup_generator(),
        <CP as CircuitParameters>::InnerCurveScalarField::zero(),
        &mut note_commitments,
        &mut nc_en_list,
        &mut rng,
    );

    // The note is spent, and a new note is created for Bob
    let output_note = alice
        .send(
            &mut vec![&spent_note],
            vec![(&bob, 1_u32)],
            &mut rng,
            &bob,
            &mut nullifier_tree,
            &mut note_commitments,
            &mut nc_en_list,
        )
        .swap_remove(0);

    // ACTION CIRCUIT CHECKS //
    // Checks follow: https://github.com/heliaxdev/taiga/blob/main/book/src/spec.md#action-circuit
    spent_notes_checks(
        &alice,
        &xan,
        &spent_note,
        &output_note,
        &mut note_commitments,
        &mut rng,
    );
    output_notes_checks(&alice, &bob, &xan, &output_note, &mut rng);
    // FRESH COMMITS (over `CP::CurveScalarField` and `CP::CurveBaseField`)

    // BLINDING CHECK
    // Action::<CP>::action_blinding(); // for token
    // Action::<CP>::action_blinding(); // for Alice send vp
    // Action::<CP>::action_blinding(); // for Bob recv vp
}

#[test]
fn test_action_conditions_kzg() {
    _action_checks::<crate::circuit::circuit_parameters::PairingCircuitParameters>();
}
