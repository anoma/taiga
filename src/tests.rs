use crate::el_gamal::{Ciphertext, DecryptionKey};
use crate::{add_to_tree, circuit::circuit_parameters::CircuitParameters, circuit::validity_predicate::{recv_gadget, send_gadget, token_gadget}, note::Note, serializable_to_vec, token::Token, user::User};
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
use ark_ff::Zero;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::constraint_system::StandardComposer;

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

    let mut rng = rand::thread_rng();

    let xan = spawn_token::<CP>("XAN");
    let _usdt = spawn_token::<CP>("USDT");

    let alice = spawn_user::<CP>("alice");
    let bob = spawn_user::<CP>("bob");

    let mut NFtree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut MTtree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut CM_CE_list: Vec<(
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

    //tx level processing
    let note_a1xan_ec = alice.encrypt(&mut rng, &note_a1xan);
    add_to_tree(&note_a1xan.commitment(), &mut MTtree);
    CM_CE_list.push((note_a1xan.commitment(), note_a1xan_ec));

    // The note is spent, and a new note is created for Bob
    let note_b1xan = alice
        .send(
            &mut vec![&note_a1xan],
            vec![(bob.address(), 1_u32)],
            &mut rng,
            &mut NFtree,
        )
        .swap_remove(0);

    add_to_tree(&note_b1xan.commitment(), &mut MTtree);

    // TODO: Replace with a more efficient implementation
    // nullifier proof
    let proof_nf = NFtree.proof(&[0]);
    let root_nf = NFtree.root().unwrap();
    let nullifier = alice.compute_nullifier(&note_a1xan);

    let mut bytes = serializable_to_vec(&nullifier);
    let hash_nf = Blake2s::hash(&bytes);
    assert!(proof_nf.verify(root_nf, &[0], &[hash_nf], 1));

    // note commitment proof
    let proof_nc = MTtree.proof(&[0, 1]);
    let root_nc = MTtree.root().unwrap();

    bytes = serializable_to_vec(&note_a1xan.commitment());
    let hash_nc_alice = Blake2s::hash(&bytes);

    bytes = serializable_to_vec(&note_b1xan.commitment());
    let hash_nc_bob = Blake2s::hash(&bytes);

    assert!(proof_nc.verify(root_nc, &[0, 1], &[hash_nc_alice, hash_nc_bob], 2));
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
    use rs_merkle::{algorithms::Blake2s, MerkleTree};

    let mut rng = ThreadRng::default();

    // users and token
    let yulia = spawn_user::<CP>("yulia");
    let simon = spawn_user::<CP>("simon");
    let xan = spawn_token::<CP>("xan");

    // bookkeeping structures
    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut nc_tree = MerkleTree::<Blake2s>::from_leaves(&vec![]);
    let mut nc_en_list: Vec<(
        TEGroupAffine<CP::InnerCurve>,
        Vec<Ciphertext<CP::InnerCurve>>,
    )> = vec![];

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
        vec![(yulia.address(), 1), (yulia.address(), 1), (simon.address(), 2)],
        &mut rng,
        &mut nf_tree,
    );

    assert_eq!(new_notes.len(), 3);
    assert_eq!(new_notes[0].value, 1);
    assert_eq!(new_notes[1].value, 1);
    assert_eq!(new_notes[2].value, 2);

    let new_notes = yulia.send(
        &mut vec![&new_notes[0], &new_notes[1]],
        vec![(yulia.address(), 2)],
        &mut rng,
        &mut nf_tree,
    );

    assert_eq!(new_notes.len(), 1);
    assert_eq!(new_notes[0].value, 2);
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
