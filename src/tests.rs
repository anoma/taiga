use crate::action::{ActionInfo, OutputInfo, SpendInfo};
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::merkle_tree::{MerklePath, MerkleTreeLeafs, TAIGA_COMMITMENT_TREE_DEPTH};
use crate::nullifier::Nullifier;
use crate::poseidon::WIDTH_3;
use crate::user::UserSendAddress;
// use crate::transaction::Transaction;
use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
use crate::{note::Note, token::Token, user::User};
use ark_ff::Zero;
use ark_std::UniformRand;
use plonk_hashing::poseidon::constants::PoseidonConstants;

#[test]
fn test_send() {
    // create a user and a note owned by this user
    // create a second user
    // compute the (partial) action circuit corresponding to sending the note to the second user
    // the note commitment is stored in a merkle tree for the action proof.
    type Fr = <CP as CircuitParameters>::CurveScalarField;

    //Create global structures
    let mut rng = ark_std::test_rng();
    let mut cms: Vec<Fr> = vec![Fr::zero(); 1 << TAIGA_COMMITMENT_TREE_DEPTH];
    // we modify `cms` at `index` for updating `cms` with a new note commitment
    let mut index: usize = 0;

    // Create users and tokens to exchange
    let xan = Token::<CP>::new(&mut rng);
    let alice = User::<CP>::new(&mut rng);
    let bob = User::<CP>::new(&mut rng);

    // Create a 1XAN note for Alice
    let note_alice_1xan = Note::<CP>::new(
        alice,
        xan,
        1,
        Nullifier::new(Fr::rand(&mut rng)),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    );

    let hasher: PoseidonConstants<Fr> = PoseidonConstants::generate::<WIDTH_3>();

    // Add note to the note commitments Merkle tree
    // Todo: do we need to do the same for the nullifier tree ?
    // It seems to be an output of the proof and does not requires a membership proof?
    cms[index] = note_alice_1xan.commitment().unwrap().inner();
    let merkle_path: MerklePath<Fr, PoseidonConstants<Fr>> =
        MerklePath::build_merkle_path(&cms, index);
    index += 1;
    let mk_root = MerkleTreeLeafs::<Fr, PoseidonConstants<Fr>>::new(cms.to_vec()).root(&hasher);

    // Action
    let spend_info = SpendInfo::<CP>::new(note_alice_1xan, merkle_path, &hasher);
    let output_info = OutputInfo::<CP>::new(
        UserSendAddress::from_closed(alice.address().unwrap()),
        bob.recv_vp,
        xan.token_vp,
        1,
        Fr::rand(&mut rng),
    );
    let action_info = ActionInfo::<CP>::new(spend_info, output_info);
    let (action, mut action_circuit) = action_info.build(&mut rng).unwrap();
    // we could create the action proof and verify it here (see `src/circuit/action_circuit.rs` for details).

    // creation of the Bob's note
    // TODO
    let output_notes_and_ec = alice.send(&mut [&note_alice_1xan], vec![(&bob, 1_u32)], &mut rng);

    // create a transaction
    // TODO
    let tx: Transaction<CP> = Transaction::new(
        vec![],
        vec![(note_a1xan, nullifier)],
        output_notes_and_ec,
        &vps,
    );
    tx.process(&mut nf_tree, &mut mt_tree, &mut cm_ce_list);
}

/*

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
    use ark_std::UniformRand;
    // --- SET UP ---

    //Create global structures
    let mut rng = ThreadRng::default();

    let mut nf_tree = MerkleTree::<Blake2s>::from_leaves(&[]);
    let mut mt_tree = MerkleTree::<Blake2s>::from_leaves(&[]);
    let mut cm_ce_list = Vec::new();

    //Create users and tokens
    let mut rng = ark_std::test_rng();
    let yulia = User::<CP>::new(&mut rng);
    let simon = User::<CP>::new(&mut rng);
    let xan = Token::<CP>::new(&mut rng);

    //Create VPs for the users and tokens
    let vps = spawn_trivial_vps(3, &mut rng);

    //Create the initial note
    let initial_note = Note::<CP>::new(
        yulia,
        xan,
        4,
        Nullifier::<CP>::new(CP::CurveScalarField::one()),
        <CP>::CurveScalarField::zero(),
        <CP as CircuitParameters>::CurveScalarField::rand(&mut rng),
    );

    add_to_tree(&initial_note.get_cm_bytes(), &mut mt_tree);
    // let initial_note_ec = yulia.encrypt(&mut rng, &initial_note);
    // cm_ce_list.push((initial_note.commitment(), initial_note_ec));

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

#[test]
fn split_and_merge_notes_test_kzg() {
    split_and_merge_notes_test::<crate::circuit::circuit_parameters::PairingCircuitParameters>();
}
*/
