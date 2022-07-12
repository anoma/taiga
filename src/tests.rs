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
use plonk_core::circuit::{Circuit, VerifierData, verify_proof};
use plonk_core::proof_system::pi::PublicInputs;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use ark_poly_commit::PolynomialCommitment;

#[test]
fn test_send() {
    // create a user and a note owned by this user
    // create a second user
    // compute the (partial) action circuit corresponding to sending the note to the second user
    // the note commitment is stored in a merkle tree for the action proof.
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type PC = <CP as CircuitParameters>::CurvePC;
    type P = <CP as CircuitParameters>::InnerCurve;

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

    // Proof computation
    let pp = PC::setup(action_circuit.padded_circuit_size(), None, &mut rng).unwrap();
    let (pk_p, vk) = action_circuit.compile::<PC>(&pp).unwrap();
    let (proof, pi) = action_circuit.gen_proof::<PC>(&pp, pk_p, b"Test").unwrap();
    let mut expect_pi = PublicInputs::new(action_circuit.padded_circuit_size());
    expect_pi.insert(24766, action.root);
    expect_pi.insert(10781, action.nf.inner());
    expect_pi.insert(31822, action.cm.inner());
    assert_eq!(pi, expect_pi);
    let verifier_data = VerifierData::new(vk, expect_pi);
    verify_proof::<Fr, P, PC>(&pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();

    // creation of the Bob's note
    let note_bob_1xan = Note::<CP>::new(
        bob,
        xan,
        1,
        action.nf,
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    );

}
