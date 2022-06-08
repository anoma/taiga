use crate::el_gamal::{Ciphertext, DecryptionKey};
use crate::{add_to_tree, circuit::circuit_parameters::CircuitParameters, circuit::validity_predicate::{recv_gadget, send_gadget, token_gadget}, note::Note, serializable_to_vec, token::Token, user::User};
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
use ark_ff::Zero;
use ark_poly_commit::PolynomialCommitment;
use crate::transaction::Transaction;

fn spawn_user<CP: CircuitParameters>(name: &str) -> User<CP> {
    use rand::rngs::ThreadRng;

    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();
    let outer_curve_pp =
        <CP as CircuitParameters>::OuterCurvePC::setup(1 << 4, None, &mut rng).unwrap();

    User::<CP>::new(
        name,
        &pp,
        &outer_curve_pp,
        DecryptionKey::<CP::InnerCurve>::new(&mut rng),
        &mut rng,
    )
}

fn spawn_token<CP: CircuitParameters>(name: &str) -> Token<CP> {
    use rand::rngs::ThreadRng;

    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();

    Token::<CP>::new(name, &pp, &mut rng)
}

fn test_send<CP: CircuitParameters>() {
    use rs_merkle::{algorithms::Blake2s, Hasher, MerkleTree};

    // --- Preparations ---

    let mut rng = rand::thread_rng();

    let xan = spawn_token::<CP>("XAN");

    let alice = spawn_user::<CP>("alice");
    let bob = spawn_user::<CP>("bob");

    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut mt_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut cm_ce_list: Vec<(
        TEGroupAffine<CP::InnerCurve>,
        Vec<Ciphertext<CP::InnerCurve>>,
    )> = vec![];

    // Creation of a note of 1XAN for Alice
    let note_a1xan = Note::<CP>::new(
        alice.address(),
        xan.address(),
        1,
        TEGroupAffine::prime_subgroup_generator(),
        <CP>::InnerCurveScalarField::zero(),
        &mut rng,
    );

    let note_a1xan_ec = alice.encrypt(&mut rng, &note_a1xan);
    add_to_tree(&note_a1xan.commitment(), &mut mt_tree);
    cm_ce_list.push((note_a1xan.commitment(), note_a1xan_ec));

    let bytes = serializable_to_vec(&note_a1xan.commitment());
    let hash_nc_alice = Blake2s::hash(&bytes);

    // --- Preparations end ---

    let created_notes_and_ec = alice
        .send(
            &mut vec![&note_a1xan],
            vec![(&bob, 1_u32)],
            &mut rng,
        );

    let hash_nc_bob = Blake2s::hash(&serializable_to_vec(&created_notes_and_ec[0].0.commitment()));

    let nullifier = alice.compute_nullifier(&note_a1xan);
    let hash_nf = Blake2s::hash(&serializable_to_vec(&nullifier));

    let tx: Transaction<CP> = Transaction::new(vec![], vec![note_a1xan], created_notes_and_ec, vec![]);
    tx.process(&mut nf_tree, &mut mt_tree, &mut cm_ce_list);

    let proof_nf = nf_tree.proof(&[0]);
    let root_nf = nf_tree.root().unwrap();
    assert!(proof_nf.verify(root_nf, &[0], &[hash_nf], 1));

    let proof_mt = mt_tree.proof(&[0, 1]);
    let root_mt = mt_tree.root().unwrap();
    assert!(proof_mt.verify(root_mt, &[0, 1], &[hash_nc_alice, hash_nc_bob], 2));
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
    use rand::rngs::ThreadRng;

    let mut rng = ThreadRng::default();

    // users and token
    let yulia = spawn_user::<CP>("yulia");
    let simon = spawn_user::<CP>("simon");
    let xan = spawn_token::<CP>("xan");

    // bookkeeping structures
//    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
//    let mut nc_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
//    let mut nc_en_list: Vec<(
//        TEGroupAffine<CP::InnerCurve>,
//        Vec<Ciphertext<CP::InnerCurve>>,
//    )> = vec![];

    // airdrop 🪂
    let initial_note = Note::<CP>::new(
        yulia.address(),
        xan.address(),
        4,
        TEGroupAffine::prime_subgroup_generator(),
        <CP as CircuitParameters>::InnerCurveScalarField::rand(&mut rng),
        &mut rng,
    );

    // …and ship it 🛳️
    let new_notes = yulia.send(
        &mut vec![&initial_note],
        vec![(&yulia, 1), (&yulia, 1), (&simon, 2)],
        &mut rng,
    );

    assert_eq!(new_notes.len(), 3);
    assert_eq!(new_notes[0].0.value, 1);
    assert_eq!(new_notes[1].0.value, 1);
    assert_eq!(new_notes[2].0.value, 2);

    let new_notes = yulia.send(
        &mut vec![&new_notes[0].0, &new_notes[1].0],
        vec![(&yulia, 2)],
        &mut rng,
    );

    assert_eq!(new_notes.len(), 1);
    assert_eq!(new_notes[0].0.value, 2);
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
