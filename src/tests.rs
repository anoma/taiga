use crate::el_gamal::{DecryptionKey, EncryptedNote};

use crate::circuit::validity_predicate::ValidityPredicate;
use crate::circuit::{circuit_parameters::CircuitParameters, gadgets::gadget::trivial_gadget};
use crate::transaction::Transaction;
use crate::{
    add_to_tree, note::Note, serializable_to_vec, token::Token, user::User,
};
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
use ark_ff::Zero;
use ark_poly_commit::PolynomialCommitment;
use rand::rngs::ThreadRng;
use rs_merkle::algorithms::Blake2s;
use rs_merkle::{Hasher, MerkleTree};

fn spawn_user<CP: CircuitParameters>(name: &str) -> User<CP> {
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();
    let outer_curve_pp =
        <CP as CircuitParameters>::OuterCurvePC::setup(1 << 4, None, &mut rng).unwrap();

    User::<CP>::new(
        name,
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
    )
}

fn spawn_token<CP: CircuitParameters>(name: &str) -> Token<CP> {
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();

    Token::<CP>::new(name, &pp, trivial_gadget::<CP>, &mut rng)
}

fn spawn_trivial_vps<CP: CircuitParameters>(
    i: usize,
    rng: &mut ThreadRng,
) -> Vec<ValidityPredicate<CP>> {
    let pp = <CP as CircuitParameters>::CurvePC::setup(2 * 300, None, rng).unwrap();
    (0..i)
        .map(|_| {
            ValidityPredicate::<CP>::new(&pp, trivial_gadget::<CP>, &vec![], &vec![], true, rng)
        })
        .collect()
}

fn test_send<CP: CircuitParameters>() {

    // --- SET UP ---

    //Create global structures
    let mut rng = rand::thread_rng();
    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut mt_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut cm_ce_list: Vec<(TEGroupAffine<CP::InnerCurve>, EncryptedNote<CP::InnerCurve>)> =
        vec![];

    //Create users and tokens to exchange
    let xan = spawn_token::<CP>("XAN");
    let alice = spawn_user::<CP>("alice");
    let bob = spawn_user::<CP>("bob");

    //Create VPs for the users and tokens
    let vps = spawn_trivial_vps(3, &mut rng);

    // Create a 1XAN note for Alice
    let note_a1xan = Note::<CP>::new(
        alice.address(),
        xan.address(),
        1,
        TEGroupAffine::prime_subgroup_generator(),
        <CP>::InnerCurveScalarField::zero(),
        &mut rng,
    );

    //Add note to the global structures
    add_to_tree(&note_a1xan.commitment(), &mut mt_tree);
    let note_a1xan_ec = alice.encrypt(&mut rng, &note_a1xan);
    cm_ce_list.push((note_a1xan.commitment(), note_a1xan_ec));

    //Prepare the hash for future MTtree membership check
    let hash_nc_alice = Blake2s::hash(&serializable_to_vec(&note_a1xan.commitment()));

    //Check that Alice's note has been created
    let proof_mt = mt_tree.proof(&[0]);
    let root_mt = mt_tree.root().unwrap();
    assert!(proof_mt.verify(root_mt, &[0], &[hash_nc_alice], 1));

    // --- SET UP END ---

    //Generate the output notes
    let output_notes_and_ec = alice.send(&mut vec![&note_a1xan], vec![(&bob, 1_u32)], &mut rng);

    //Prepare the hash for future MTtree membership check
    let bytes = serializable_to_vec(&output_notes_and_ec[0].0.commitment());
    let hash_nc_bob = Blake2s::hash(&bytes);

    //Prepare the nf hash for future spent notes check
    let nullifier = alice.compute_nullifier(&note_a1xan);
    let hash_nf = Blake2s::hash(&serializable_to_vec(&nullifier));

    //Create a tx spending Alice's note and creating a note for Bob
    let tx: Transaction<CP> = Transaction::new(
        vec![],
        vec![(note_a1xan, nullifier)],
        output_notes_and_ec,
        &vps,
    );
    tx.process(&mut nf_tree, &mut mt_tree, &mut cm_ce_list);

    //Check that Alice's note has been spent
    let proof_nf = nf_tree.proof(&[0]);
    let root_nf = nf_tree.root().unwrap();
    assert!(proof_nf.verify(root_nf, &[0], &[hash_nf], 1));

    //Check that Bob's note has been created
    let proof_mt = mt_tree.proof(&[1]);
    let root_mt = mt_tree.root().unwrap();
    assert!(proof_mt.verify(root_mt, &[1], &[hash_nc_bob], 2));
}

// // We decided to continue with KZG for now
// #[test]
// fn test_send_ipa() {
//     test_send::<crate::circuit::circuit_parameters::DLCircuitParameters>();
// }

#[test]
fn test_send_kzg() {
    test_send::<crate::circuit::circuit_parameters::PairingCircuitParameters>();
}

fn test_check_proofs<CP: CircuitParameters>() {
    spawn_user::<CP>("Ferdinand").check_proofs();
}

#[test]
fn test_check_proofs_kzg() {
    test_check_proofs::<crate::circuit::circuit_parameters::PairingCircuitParameters>();
}

fn split_and_merge_notes_test<CP: CircuitParameters>() {
    use ark_ff::UniformRand;

    // --- SET UP ---

    //Create global structures
    let mut rng = ThreadRng::default();

    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut mt_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut cm_ce_list: Vec<(TEGroupAffine<CP::InnerCurve>, EncryptedNote<CP::InnerCurve>)> =
        vec![];

    //Create users and tokens
    let yulia = spawn_user::<CP>("yulia");
    let simon = spawn_user::<CP>("simon");
    let xan = spawn_token::<CP>("xan");

    //Create VPs for the users and tokens
    let vps = spawn_trivial_vps(3, &mut rng);

    //Create the initial note
    let initial_note = Note::<CP>::new(
        yulia.address(),
        xan.address(),
        4,
        TEGroupAffine::prime_subgroup_generator(),
        <CP as CircuitParameters>::InnerCurveScalarField::rand(&mut rng),
        &mut rng,
    );

    add_to_tree(&initial_note.commitment(), &mut mt_tree);
    let initial_note_ec = yulia.encrypt(&mut rng, &initial_note);
    cm_ce_list.push((initial_note.commitment(), initial_note_ec));

    //Prepare the hash for future MTtree membership check
    let hash_in = Blake2s::hash(&serializable_to_vec(&initial_note.commitment()));

    //Check that the note has been created
    let proof_mt = mt_tree.proof(&[0]);
    let root_mt = mt_tree.root().unwrap();
    assert!(proof_mt.verify(root_mt, &[0], &[hash_in], 1));

    // --- SET UP END ---

    // Split a note between users
    let split_output_notes = yulia.send(
        &mut vec![&initial_note],
        vec![(&yulia, 1), (&yulia, 1), (&simon, 2)],
        &mut rng,
    );

    //Prepare the hashes for future MTtree membership check
    let mut bytes = serializable_to_vec(&split_output_notes[0].0.commitment());
    let hash1 = Blake2s::hash(&bytes);
    bytes = serializable_to_vec(&split_output_notes[1].0.commitment());
    let hash2 = Blake2s::hash(&bytes);
    bytes = serializable_to_vec(&split_output_notes[2].0.commitment());
    let hash3 = Blake2s::hash(&bytes);

    //Prepare the nf hash for future spent notes check
    let nullifier = yulia.compute_nullifier(&initial_note);
    let hash_nf = Blake2s::hash(&serializable_to_vec(&nullifier));

    //Create a tx splitting the initial note
    let tx: Transaction<CP> = Transaction::new(
        vec![],
        vec![(initial_note, nullifier)],
        split_output_notes.clone(),
        &vps,
    );
    tx.process(&mut nf_tree, &mut mt_tree, &mut cm_ce_list);

    //Check the amount of output notes and their values
    assert_eq!(split_output_notes.len(), 3);
    assert_eq!(split_output_notes[0].0.value, 1);
    assert_eq!(split_output_notes[1].0.value, 1);
    assert_eq!(split_output_notes[2].0.value, 2);

    //Check that the initial note has been spent
    let proof_nf = nf_tree.proof(&[0]);
    let root_nf = nf_tree.root().unwrap();
    assert!(proof_nf.verify(root_nf, &[0], &[hash_nf], 1));

    //Check that the notes has been added to the tree
    let proof_mt = mt_tree.proof(&[1, 2, 3]);
    let root_mt = mt_tree.root().unwrap();
    assert!(proof_mt.verify(root_mt, &[1, 2, 3], &[hash1, hash2, hash3], 4));

    let merge_output_notes = yulia.send(
        &mut vec![&split_output_notes[0].0, &split_output_notes[1].0],
        vec![(&yulia, 2)],
        &mut rng,
    );

    //Prepare the hash for future MTtree membership check
    bytes = serializable_to_vec(&merge_output_notes[0].0.commitment());
    let hash4 = Blake2s::hash(&bytes);

    //Prepare the nf hash for future spent notes check
    let nullifier1 = yulia.compute_nullifier(&split_output_notes[0].0);
    let nullifier2 = yulia.compute_nullifier(&split_output_notes[1].0);
    let hash_nf1 = Blake2s::hash(&serializable_to_vec(&nullifier1));
    let hash_nf2 = Blake2s::hash(&serializable_to_vec(&nullifier2));

    //Create a tx splitting the initial note
    let tx: Transaction<CP> = Transaction::new(
        vec![],
        vec![
            (split_output_notes[0].0.clone(), nullifier1),
            (split_output_notes[1].0.clone(), nullifier2),
        ],
        merge_output_notes.clone(),
        &vps,
    );
    tx.process(&mut nf_tree, &mut mt_tree, &mut cm_ce_list);

    //Check the amount of notes and their values
    assert_eq!(merge_output_notes.len(), 1);
    assert_eq!(merge_output_notes[0].0.value, 2);

    //Check that the notes has been spent
    let proof_nf = nf_tree.proof(&[1, 2]);
    let root_nf = nf_tree.root().unwrap();
    assert!(proof_nf.verify(root_nf, &[1, 2], &[hash_nf1, hash_nf2], 3));

    //Check that the notes has been added to the tree
    let proof_mt = mt_tree.proof(&[4]);
    let root_mt = mt_tree.root().unwrap();
    assert!(proof_mt.verify(root_mt, &[4], &[hash4], 5));
}

// // We decided to continue with KZG for now
// #[test]
// fn split_and_merge_notes_test_ipa() {
//     split_and_merge_notes_test::<crate::circuit::circuit_parameters::DLCircuitParameters>();
// }

#[test]
fn split_and_merge_notes_test_kzg() {
    split_and_merge_notes_test::<crate::circuit::circuit_parameters::PairingCircuitParameters>();
}
