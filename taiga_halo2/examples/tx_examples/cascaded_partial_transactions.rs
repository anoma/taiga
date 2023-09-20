/// The example shows how to cascade the partial transactions by intents.
/// Alice wants to spend 1 "BTC", 2 "ETH" and 3 "XAN" simultaneously
///
use crate::token::create_random_token_note;
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    circuit::vp_examples::{
        cascade_intent::{create_intent_note, CascadeIntentValidityPredicateCircuit},
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{
            generate_input_token_note_proving_info, generate_output_token_note_proving_info,
            TokenAuthorization,
        },
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteProvingInfo, OutputNoteProvingInfo},
    nullifier::{Nullifier, NullifierKeyContainer},
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};

pub fn create_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth = TokenAuthorization::from_sk_vk(&alice_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);
    let alice_nk = NullifierKeyContainer::random_key(&mut rng);

    let bob_auth = TokenAuthorization::random(&mut rng);
    let bob_nk_com = NullifierKeyContainer::random_commitment(&mut rng);

    let rho = Nullifier::from(pallas::Base::random(&mut rng));
    let input_note_1 = create_random_token_note(&mut rng, "btc", 1u64, rho, alice_nk, &alice_auth);
    let output_note_1 = create_random_token_note(
        &mut rng,
        "btc",
        1u64,
        input_note_1.get_nf().unwrap(),
        bob_nk_com,
        &bob_auth,
    );
    let input_note_2 = create_random_token_note(&mut rng, "eth", 2u64, rho, alice_nk, &alice_auth);

    let input_note_3 = create_random_token_note(&mut rng, "xan", 3u64, rho, alice_nk, &alice_auth);
    let cascade_intent_note = create_intent_note(
        &mut rng,
        input_note_3.commitment().inner(),
        input_note_2.get_nf().unwrap(),
        alice_nk,
    );
    let output_note_2 = create_random_token_note(
        &mut rng,
        "eth",
        2u64,
        cascade_intent_note.get_nf().unwrap(),
        bob_nk_com,
        &bob_auth,
    );
    let output_note_3 = create_random_token_note(
        &mut rng,
        "xan",
        3u64,
        input_note_3.get_nf().unwrap(),
        bob_nk_com,
        &bob_auth,
    );

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // The first partial transaction:
    // Alice consumes 1 "BTC" and 2 "ETH".
    // Alice creates a cascade intent note and 1 "BTC" to Bob.
    let ptx_1 = {
        let input_notes = [input_note_1, input_note_2];
        let output_notes = [output_note_1, cascade_intent_note];
        // Create the input note proving info
        let input_note_1_proving_info = generate_input_token_note_proving_info(
            &mut rng,
            input_note_1,
            "btc".to_string(),
            alice_auth,
            alice_auth_sk,
            merkle_path.clone(),
            input_notes,
            output_notes,
        );
        let input_note_2_proving_info = generate_input_token_note_proving_info(
            &mut rng,
            input_note_2,
            "eth".to_string(),
            alice_auth,
            alice_auth_sk,
            merkle_path.clone(),
            input_notes,
            output_notes,
        );

        // Create the output note proving info
        let output_note_1_proving_info = generate_output_token_note_proving_info(
            &mut rng,
            output_note_1,
            "btc".to_string(),
            bob_auth,
            input_notes,
            output_notes,
        );

        let intent_note_proving_info = {
            let intent_vp = CascadeIntentValidityPredicateCircuit {
                owned_note_pub_id: cascade_intent_note.commitment().inner(),
                input_notes,
                output_notes,
                cascade_note_cm: cascade_intent_note.get_app_data_static(),
            };

            OutputNoteProvingInfo::new(cascade_intent_note, Box::new(intent_vp), vec![])
        };

        // Create shielded partial tx
        ShieldedPartialTransaction::build(
            [input_note_1_proving_info, input_note_2_proving_info],
            [output_note_1_proving_info, intent_note_proving_info],
            &mut rng,
        )
    };

    // The second partial transaction:
    // Alice consumes the intent note and 3 "XAN";
    // Alice creates 2 "ETH" and 3 "XAN" to Bob
    let ptx_2 = {
        let input_notes = [cascade_intent_note, input_note_3];
        let output_notes = [output_note_2, output_note_3];
        // Create the input note proving info
        let intent_note_proving_info = {
            let intent_vp = CascadeIntentValidityPredicateCircuit {
                owned_note_pub_id: cascade_intent_note.get_nf().unwrap().inner(),
                input_notes,
                output_notes,
                cascade_note_cm: cascade_intent_note.get_app_data_static(),
            };

            InputNoteProvingInfo::new(
                cascade_intent_note,
                merkle_path.clone(),
                Box::new(intent_vp),
                vec![],
            )
        };
        let input_note_3_proving_info = generate_input_token_note_proving_info(
            &mut rng,
            input_note_3,
            "xan".to_string(),
            alice_auth,
            alice_auth_sk,
            merkle_path,
            input_notes,
            output_notes,
        );
        // Create the output note proving info
        let output_note_2_proving_info = generate_output_token_note_proving_info(
            &mut rng,
            output_note_2,
            "eth".to_string(),
            bob_auth,
            input_notes,
            output_notes,
        );
        let output_note_3_proving_info = generate_output_token_note_proving_info(
            &mut rng,
            output_note_3,
            "xan".to_string(),
            bob_auth,
            input_notes,
            output_notes,
        );

        // Create shielded partial tx
        ShieldedPartialTransaction::build(
            [intent_note_proving_info, input_note_3_proving_info],
            [output_note_2_proving_info, output_note_3_proving_info],
            &mut rng,
        )
    };

    // Create the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::build(vec![ptx_1, ptx_2]);
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(&mut rng, shielded_tx_bundle, transparent_ptx_bundle)
}

#[test]
fn test_cascade_ptxs() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_transaction(&mut rng);
    tx.execute().unwrap();
}
