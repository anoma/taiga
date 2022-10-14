use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::trivial::trivial_gadget;
use crate::nullifier::Nullifier;
use crate::circuit::validity_predicate::ValidityPredicate;
use crate::el_gamal::DecryptionKey;
use crate::transaction::Transaction;
use crate::{add_to_tree, note::Note, serializable_to_vec, app::App, user::User};
use ark_ff::{One, Zero};
use ark_poly_commit::PolynomialCommitment;
use rand::rngs::ThreadRng;
use rs_merkle::algorithms::Blake2s;
use rs_merkle::{Hasher, MerkleTree};

fn spawn_user<CP: CircuitParameters>(name: &str) -> User<CP> {
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();
    let outer_curve_pp =
        <CP as CircuitParameters>::OuterCurvePC::setup(1 << 13, None, &mut rng).unwrap();

    User::<CP>::new(
        name,
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
    )
}

fn spawn_app<CP: CircuitParameters>(name: &str) -> App<CP> {
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();

    App::<CP>::new(name, &pp, trivial_gadget::<CP>, &mut rng)
}

fn spawn_trivial_vps<CP: CircuitParameters>(
    i: usize,
    rng: &mut ThreadRng,
) -> Vec<ValidityPredicate<CP>> {
    let pp = <CP as CircuitParameters>::CurvePC::setup(2 * 300, None, rng).unwrap();
    (0..i)
        .map(|_| ValidityPredicate::<CP>::new(&pp, trivial_gadget::<CP>, &[], &[], true, rng))
        .collect()
}

fn test_send<CP: CircuitParameters>() {
    // --- SET UP ---

    //Create global structures
    let mut rng = rand::thread_rng();
    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&[]);
    let mut mt_tree = MerkleTree::<Blake2s>::from_leaves(&[]);
    let mut cm_ce_list = Vec::new();

    //Create users and apps to exchange
    let xan = spawn_app::<CP>("XAN");
    let alice = spawn_user::<CP>("alice");
    let bob = spawn_user::<CP>("bob");

    //Create VPs for the users and apps
    let vps = spawn_trivial_vps(3, &mut rng);

    // Create a 1XAN note for Alice
    let note_a1xan = Note::<CP>::new(
        alice.address(),
        xan.address(),
        1,
        <CP>::CurveScalarField::one(),
        <CP>::CurveScalarField::zero(),
        &mut rng,
    );

    //Add note to the global structures
    add_to_tree(&note_a1xan.get_cm_bytes(), &mut mt_tree);
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
    let output_notes_and_ec = alice.send(&mut [&note_a1xan], vec![(&bob, 1_u32)], &mut rng);

    //Prepare the hash for future MTtree membership check
    let bytes = serializable_to_vec(&output_notes_and_ec[0].0.commitment());
    let hash_nc_bob = Blake2s::hash(&bytes);

    //Prepare the nf hash for future spent notes check
    let nullifier = Nullifier::derive_native(
        &alice.get_nk(),
        &note_a1xan.rho,
        &note_a1xan.psi,
        &note_a1xan.commitment(),
    );
    let hash_nf = Blake2s::hash(&nullifier.to_bytes());

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
    // --- SET UP ---

    //Create global structures
    let mut rng = ThreadRng::default();

    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&[]);
    let mut mt_tree = MerkleTree::<Blake2s>::from_leaves(&[]);
    let mut cm_ce_list = Vec::new();

    //Create users and apps
    let yulia = spawn_user::<CP>("yulia");
    let simon = spawn_user::<CP>("simon");
    let xan = spawn_app::<CP>("xan");

    //Create VPs for the users and apps
    let vps = spawn_trivial_vps(3, &mut rng);

    //Create the initial note
    let initial_note = Note::<CP>::new(
        yulia.address(),
        xan.address(),
        4,
        <CP>::CurveScalarField::one(),
        <CP>::CurveScalarField::zero(),
        &mut rng,
    );

    add_to_tree(&initial_note.get_cm_bytes(), &mut mt_tree);
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
        &mut [&initial_note],
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
    let nullifier = Nullifier::derive_native(
        &yulia.get_nk(),
        &initial_note.rho,
        &initial_note.psi,
        &initial_note.commitment(),
    );
    let hash_nf = Blake2s::hash(&nullifier.to_bytes());

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
        &mut [&split_output_notes[0].0, &split_output_notes[1].0],
        vec![(&yulia, 2)],
        &mut rng,
    );

    //Prepare the hash for future MTtree membership check
    bytes = serializable_to_vec(&merge_output_notes[0].0.commitment());
    let hash4 = Blake2s::hash(&bytes);

    //Prepare the nf hash for future spent notes check
    let nullifier1 = Nullifier::derive_native(
        &yulia.get_nk(),
        &split_output_notes[0].0.rho,
        &split_output_notes[0].0.psi,
        &split_output_notes[0].0.commitment(),
    );
    let nullifier2 = Nullifier::derive_native(
        &yulia.get_nk(),
        &split_output_notes[1].0.rho,
        &split_output_notes[1].0.psi,
        &split_output_notes[1].0.commitment(),
    );
    let hash_nf1 = Blake2s::hash(&nullifier1.to_bytes());
    let hash_nf2 = Blake2s::hash(&nullifier2.to_bytes());

    //Create a tx splitting the initial note
    let tx: Transaction<CP> = Transaction::new(
        vec![],
        vec![
            (split_output_notes[0].0, nullifier1),
            (split_output_notes[1].0, nullifier2),
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
