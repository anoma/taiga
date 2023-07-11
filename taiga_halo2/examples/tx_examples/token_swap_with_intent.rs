/// Token swap example with intent note
/// Alice has 5 "BTC" and wants 1 "DOLPHIN" or 2 "Monkeys". Then Alice creates an intent for it.
/// Bob has 1 "DOLPHIN" and wants 5 "BTC".
/// The Solver/Bob matches Alice's intent and creates the final tx.
///
use crate::token::{create_random_token_note, create_token_swap_ptx};
use group::Group;
use halo2_proofs::arithmetic::Field;
use pasta_curves::{group::Curve, pallas};
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    circuit::vp_examples::{
        or_relation_intent::{
            create_intent_note, Condition, OrRelationIntentValidityPredicateCircuit,
        },
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{
            generate_input_token_note_proving_info, generate_output_token_note_proving_info,
            TokenAuthorization,
        },
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteProvingInfo, Note, OutputNoteProvingInfo},
    nullifier::{Nullifier, NullifierKey},
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
    input_nk: NullifierKey, // NullifierKey::Open
) -> (
    ShieldedPartialTransaction,
    pallas::Scalar,
    NullifierKey,
    pallas::Base,
    Nullifier,
) {
    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);

    // input note
    let rho = Nullifier::new(pallas::Base::random(&mut rng));
    let input_note = create_random_token_note(
        &mut rng,
        input_token,
        input_value,
        rho,
        input_nk,
        &input_auth,
    );

    // output intent note
    // Use the same address as that in the input note. They can be different.
    let receiver_address = input_note.get_address();
    let input_note_nf = input_note.get_nf().unwrap();
    let intent_note = create_intent_note(
        &mut rng,
        &condition1,
        &condition2,
        receiver_address,
        input_note_nf,
        input_nk,
    );

    // padding the zero notes
    let padding_input_note = Note::dummy_zero_note(&mut rng, rho);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::dummy_zero_note(&mut rng, padding_input_note_nf);

    let input_notes = [input_note, padding_input_note];
    let output_notes = [intent_note, padding_output_note];

    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create the input note proving info
    let input_note_proving_info = generate_input_token_note_proving_info(
        &mut rng,
        input_note,
        input_token.to_string(),
        input_auth,
        input_auth_sk,
        merkle_path.clone(),
        input_notes,
        output_notes,
    );

    // Create the intent note proving info
    let intent_note_proving_info = {
        let intent_vp = OrRelationIntentValidityPredicateCircuit {
            owned_note_pub_id: intent_note.commitment().get_x(),
            input_notes,
            output_notes,
            condition1,
            condition2,
            receiver_address,
        };

        OutputNoteProvingInfo::new(intent_note, Box::new(intent_vp), vec![])
    };

    // Create the padding input note proving info
    let padding_input_note_proving_info = InputNoteProvingInfo::create_padding_note_proving_info(
        padding_input_note,
        merkle_path,
        input_notes,
        output_notes,
    );

    // Create the padding output note proving info
    let padding_output_note_proving_info = OutputNoteProvingInfo::create_padding_note_proving_info(
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

    (ptx, r, input_nk, receiver_address, rho)
}

#[allow(clippy::too_many_arguments)]
pub fn consume_token_intent_ptx<R: RngCore>(
    mut rng: R,
    condition1: Condition,
    condition2: Condition,
    input_rho: Nullifier,
    input_nk: NullifierKey,
    input_address: pallas::Base,
    output_token: &str,
    output_value: u64,
    output_auth_pk: pallas::Point,
) -> (ShieldedPartialTransaction, pallas::Scalar) {
    // input intent note
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
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
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

    let input_notes = [intent_note, padding_input_note];
    let output_notes = [output_note, padding_output_note];

    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create the intent note proving info
    let intent_note_proving_info = {
        let intent_vp = OrRelationIntentValidityPredicateCircuit {
            owned_note_pub_id: input_note_nf.inner(),
            input_notes,
            output_notes,
            condition1,
            condition2,
            receiver_address: input_address,
        };

        InputNoteProvingInfo::new(
            intent_note,
            merkle_path.clone(),
            Box::new(intent_vp),
            vec![],
        )
    };

    // Create the output note proving info
    let output_note_proving_info = generate_output_token_note_proving_info(
        &mut rng,
        output_note,
        output_token.to_string(),
        output_auth,
        input_notes,
        output_notes,
    );

    // Create the padding input note proving info
    let padding_input_note_proving_info = InputNoteProvingInfo::create_padding_note_proving_info(
        padding_input_note,
        merkle_path,
        input_notes,
        output_notes,
    );

    // Create the padding output note proving info
    let padding_output_note_proving_info = OutputNoteProvingInfo::create_padding_note_proving_info(
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
    let generator = pallas::Point::generator().to_affine();

    // Alice creates the partial transaction with 5 BTC input and intent output
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth_pk = generator * alice_auth_sk;
    let alice_nk = NullifierKey::random(&mut rng);
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
    let bob_nk = NullifierKey::random(&mut rng);

    let (bob_ptx, bob_r) = create_token_swap_ptx(
        &mut rng,
        "dolphin",
        1,
        bob_auth_sk,
        bob_nk,
        "btc",
        5,
        bob_auth_pk,
        bob_nk,
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
    Transaction::build(
        &mut rng,
        Some(shielded_tx_bundle),
        None,
        vec![alice_r, bob_r, solver_r],
    )
}

#[test]
fn test_token_swap_intent_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_intent_transaction(&mut rng);
    tx.execute().unwrap();
}
