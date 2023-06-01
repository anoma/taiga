/// Token swap example with intent note
/// Alice has 5 "BTC" and wants 1 "DOLPHIN" or 2 "Monkeys". Then Alice creates an intent for it.
/// Bob has 1 "DOLPHIN" and wants 5 "BTC".
/// The Solver/Bob matches Alice's intent and creates the final tx.
///
use crate::token::{create_random_token_note, create_token_swap_ptx};
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    circuit::vp_examples::{
        or_relation_intent::{
            create_intent_note, Condition, OrRelationIntentValidityPredicateCircuit,
        },
        signature_verification::{SignatureVerificationValidityPredicateCircuit, TOKEN_AUTH_VK},
        token::{TokenAuthorization, TokenValidityPredicateCircuit},
    },
    constant::NOTE_COMMIT_DOMAIN,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteInfo, Note, OutputNoteInfo},
    nullifier::{Nullifier, NullifierDerivingKey, NullifierKeyCom},
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction},
};

pub fn create_token_intent_ptx<R: RngCore>(
    mut rng: R,
    condition1: Condition,
    condition2: Condition,
    input_token: &str,
    input_value: u64,
    input_auth_sk: pallas::Scalar,
    input_nk: NullifierDerivingKey, // NullifierKeyCom::Open
) -> (
    ShieldedPartialTransaction,
    pallas::Scalar,
    NullifierKeyCom,
    pallas::Base,
    Nullifier,
) {
    let compressed_auth_vk = TOKEN_AUTH_VK.get_compressed();

    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &compressed_auth_vk);

    // input note
    let rho = Nullifier::new(pallas::Base::random(&mut rng));
    let input_nk_com = NullifierKeyCom::from_open(input_nk);
    let inpute_note = create_random_token_note(
        &mut rng,
        input_token,
        input_value,
        rho,
        input_nk_com,
        &input_auth,
    );

    // output intent note
    // Use the same address as that in the input note. They can be different.
    let receiver_address = inpute_note.get_address();
    let input_note_nf = inpute_note.get_nf().unwrap();
    let intent_note = create_intent_note(
        &mut rng,
        &condition1,
        &condition2,
        receiver_address,
        input_note_nf,
        input_nk_com,
    );

    // padding the zero notes
    let padding_input_note = Note::dummy_zero_note(&mut rng, rho);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::dummy_zero_note(&mut rng, padding_input_note_nf);

    let input_notes = [inpute_note.clone(), padding_input_note.clone()];
    let output_notes = [intent_note.clone(), padding_output_note.clone()];

    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create the input note proving info
    let input_note_proving_info = {
        // input note token VP
        let token_vp = TokenValidityPredicateCircuit {
            owned_note_pub_id: input_note_nf.inner(),
            input_notes: input_notes.clone(),
            output_notes: output_notes.clone(),
            token_name: input_token.to_string(),
            auth: input_auth,
        };

        // token auth VP
        let token_auth_vp = SignatureVerificationValidityPredicateCircuit::from_sk_and_sign(
            &mut rng,
            input_note_nf.inner(),
            input_notes.clone(),
            output_notes.clone(),
            compressed_auth_vk,
            input_auth_sk,
        );

        // inpute note proving info
        InputNoteInfo::new(
            inpute_note,
            merkle_path.clone(),
            Box::new(token_vp),
            vec![Box::new(token_auth_vp)],
        )
    };

    // Create the intent note proving info
    let intent_note_proving_info = {
        let intent_vp = OrRelationIntentValidityPredicateCircuit {
            owned_note_pub_id: intent_note.commitment().get_x(),
            input_notes: input_notes.clone(),
            output_notes: output_notes.clone(),
            condition1,
            condition2,
            receiver_address,
        };

        OutputNoteInfo::new(intent_note, Box::new(intent_vp), vec![])
    };

    // Create the padding input note proving info
    let padding_input_note_proving_info = InputNoteInfo::create_padding_note_proving_info(
        padding_input_note,
        merkle_path,
        input_notes.clone(),
        output_notes.clone(),
    );

    // Create the padding output note proving info
    let padding_output_note_proving_info = OutputNoteInfo::create_padding_note_proving_info(
        padding_output_note,
        input_notes,
        output_notes,
    );

    // Create shielded partial tx
    let (ptx, r) = ShieldedPartialTransaction::build(
        [input_note_proving_info, padding_input_note_proving_info],
        [intent_note_proving_info, padding_output_note_proving_info],
        &mut rng,
    );

    (ptx, r, input_nk_com, receiver_address, rho)
}

#[allow(clippy::too_many_arguments)]
pub fn consume_token_intent_ptx<R: RngCore>(
    mut rng: R,
    condition1: Condition,
    condition2: Condition,
    input_rho: Nullifier,
    input_nk: NullifierKeyCom,
    input_address: pallas::Base,
    output_token: &str,
    output_value: u64,
    output_auth_pk: pallas::Point,
) -> (ShieldedPartialTransaction, pallas::Scalar) {
    let compressed_auth_vk = TOKEN_AUTH_VK.get_compressed();

    // inpute intent note
    let intent_note = create_intent_note(
        &mut rng,
        &condition1,
        &condition2,
        input_address,
        input_rho,
        input_nk,
    );

    // output note
    let input_note_nf = intent_note.get_nf().unwrap();
    let output_auth = TokenAuthorization::new(output_auth_pk, compressed_auth_vk);
    let output_note = create_random_token_note(
        &mut rng,
        output_token,
        output_value,
        input_note_nf,
        input_nk,
        &output_auth,
    );
    let address = output_note.get_address();
    assert_eq!(address, input_address);

    // padding the zero notes
    let rho = Nullifier::new(pallas::Base::random(&mut rng));
    let padding_input_note = Note::dummy_zero_note(&mut rng, rho);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::dummy_zero_note(&mut rng, padding_input_note_nf);

    let input_notes = [intent_note.clone(), padding_input_note.clone()];
    let output_notes = [output_note.clone(), padding_output_note.clone()];

    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create the intent note proving info
    let intent_note_proving_info = {
        let intent_vp = OrRelationIntentValidityPredicateCircuit {
            owned_note_pub_id: input_note_nf.inner(),
            input_notes: input_notes.clone(),
            output_notes: output_notes.clone(),
            condition1,
            condition2,
            receiver_address: input_address,
        };

        InputNoteInfo::new(
            intent_note,
            merkle_path.clone(),
            Box::new(intent_vp),
            vec![],
        )
    };

    // Create the output note proving info
    let output_note_proving_info = {
        // input note token VP
        let token_vp = TokenValidityPredicateCircuit {
            owned_note_pub_id: output_note.commitment().get_x(),
            input_notes: input_notes.clone(),
            output_notes: output_notes.clone(),
            token_name: output_token.to_string(),
            auth: output_auth,
        };

        // inpute note proving info
        OutputNoteInfo::new(output_note, Box::new(token_vp), vec![])
    };

    // Create the padding input note proving info
    let padding_input_note_proving_info = InputNoteInfo::create_padding_note_proving_info(
        padding_input_note,
        merkle_path,
        input_notes.clone(),
        output_notes.clone(),
    );

    // Create the padding output note proving info
    let padding_output_note_proving_info = OutputNoteInfo::create_padding_note_proving_info(
        padding_output_note,
        input_notes,
        output_notes,
    );

    // Create shielded partial tx
    ShieldedPartialTransaction::build(
        [intent_note_proving_info, padding_input_note_proving_info],
        [output_note_proving_info, padding_output_note_proving_info],
        &mut rng,
    )
}

pub fn create_token_swap_intent_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let generator = NOTE_COMMIT_DOMAIN.R();

    // Alice creates the partial transaction with 5 BTC input and intent output
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth_pk = generator * alice_auth_sk;
    let alice_nk_com = NullifierKeyCom::rand(&mut rng);
    let alice_nk = alice_nk_com.get_nk().unwrap();
    let condition1 = Condition {
        token_name: "dolphin".to_string(),
        token_value: 1u64,
    };
    let condition2 = Condition {
        token_name: "monkey".to_string(),
        token_value: 2u64,
    };
    let (alice_ptx, alice_r, intent_nk, receiver_address, intent_rho) = create_token_intent_ptx(
        &mut rng,
        condition1.clone(),
        condition2.clone(),
        "btc",
        5u64,
        alice_auth_sk,
        alice_nk,
    );

    // Bob creates the partial transaction with 1 DOLPHIN input and 5 BTC output
    let bob_auth_sk = pallas::Scalar::random(&mut rng);
    let bob_auth_pk = generator * bob_auth_sk;
    let bob_nk_com = NullifierKeyCom::rand(&mut rng);
    let bob_nk = bob_nk_com.get_nk().unwrap();

    let (bob_ptx, bob_r) = create_token_swap_ptx(
        &mut rng,
        "dolphin",
        1,
        bob_auth_sk,
        bob_nk,
        "btc",
        5,
        bob_auth_pk,
        bob_nk_com.get_nk_com(),
    );

    // Solver/Bob creates the partial transaction to consume the intent note
    // The bob_ptx and solver_ptx can be merged to one ptx.
    let (solver_ptx, solver_r) = consume_token_intent_ptx(
        &mut rng,
        condition1,
        condition2,
        intent_rho,
        intent_nk,
        receiver_address,
        "dolphin",
        1u64,
        alice_auth_pk,
    );

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::build(vec![alice_ptx, bob_ptx, solver_ptx]);
    let mut tx = Transaction::new(
        Some(shielded_tx_bundle),
        None,
        vec![alice_r, bob_r, solver_r],
    );
    tx.binding_sign(rng);
    tx
}

#[test]
fn test_token_swap_intent_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_intent_transaction(&mut rng);
    tx.execute().unwrap();
}
