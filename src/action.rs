use crate::circuit::gadgets::gadget::trivial_gadget;
use crate::nullifier_key::NullifierDerivingKey;
use crate::{add_to_tree, circuit::circuit_parameters::CircuitParameters, crh};
use ark_ff::One;
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
        nk: NullifierDerivingKey<CP::CurveScalarField>,
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
                            nk.inner()
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
use crate::el_gamal::DecryptionKey;
use crate::note::Note;
use crate::token::Token;
use crate::user::User;
use crate::{serializable_to_vec, to_embedded_field};
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ff::{BigInteger256, Zero};
use ark_poly_commit::PolynomialCommitment;

/// For spent note
/// `note = (address, token, v, data, ρ, ψ, rcm_note)`:
#[allow(dead_code)]
fn spent_notes_checks<CP: CircuitParameters>(
    sender: &User<CP>,
    token: &Token<CP>,
    spent_note: &Note<CP>,
    _output_note: &Note<CP>,
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
    // We don't need the nullifier check here.
    // TODO: Since there is not a action circuit implementation yet, add nullifier derivation circuit here(already
    // implemented in nullifier test) when implementing the action circuit.

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
        &[],
        &[],
        trivial_gadget::<CP>,
        &[],
        &[],
        &mut rng,
    );

    let bob = User::<CP>::new(
        "bob",
        &pp,
        &outer_curve_pp,
        DecryptionKey::<CP::InnerCurve>::new(&mut rng),
        trivial_gadget::<CP>,
        &[],
        &[],
        trivial_gadget::<CP>,
        &[],
        &[],
        &mut rng,
    );

    let xan = Token::<CP>::new("xan", &pp, trivial_gadget::<CP>, &mut rng);

    // Creation of a note commitments tree
    let mut mt_tree = MerkleTree::<Blake2s>::from_leaves(&[]);
    // Creation of the {note commitment + encrypted note} list
    let mut cm_ce_list = Vec::new();

    // Creation of a note of 1XAN for Alice
    let spent_note = Note::<CP>::new(
        alice.address(),
        xan.address(),
        1,
        CP::CurveScalarField::one(),
        CP::CurveScalarField::one(),
        &mut rng,
    );

    let spent_note_ec = alice.encrypt(&mut rng, &spent_note);
    add_to_tree(&spent_note.get_cm_bytes(), &mut mt_tree);
    cm_ce_list.push((spent_note.commitment(), spent_note_ec));

    // The note is spent, and a new note is created for Bob
    let output_note = alice
        .send(&mut [&spent_note], vec![(&bob, 1_u32)], &mut rng)
        .swap_remove(0)
        .0;

    add_to_tree(&output_note.get_cm_bytes(), &mut mt_tree);

    // ACTION CIRCUIT CHECKS //
    // Checks follow: https://github.com/heliaxdev/taiga/blob/main/book/src/spec.md#action-circuit
    spent_notes_checks(
        &alice,
        &xan,
        &spent_note,
        &output_note,
        &mut mt_tree,
        &mut rng,
    );
    output_notes_checks(&bob, &xan, &output_note, &mut rng);

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
