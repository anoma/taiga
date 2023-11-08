/// The example shows how to cascade the partial transactions by intents.
/// Alice wants to spend 1 "BTC", 2 "ETH" and 3 "XAN" simultaneously
///
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    action::ActionInfo,
    circuit::vp_examples::{
        cascade_intent::{create_intent_note, CascadeIntentValidityPredicateCircuit},
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    note::NoteValidityPredicates,
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};

pub fn create_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth = TokenAuthorization::from_sk_vk(&alice_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);
    let alice_nk = pallas::Base::random(&mut rng);

    let bob_auth = TokenAuthorization::random(&mut rng);
    let bob_nk_com = pallas::Base::random(&mut rng);

    let input_token_1 = Token::new("btc".to_string(), 1u64);
    let input_note_1 =
        input_token_1.create_random_input_token_note(&mut rng, alice_nk, &alice_auth);
    let output_token_1 = Token::new("btc".to_string(), 1u64);
    let mut output_note_1 = output_token_1.create_random_output_token_note(bob_nk_com, &bob_auth);
    let input_token_2 = Token::new("eth".to_string(), 2u64);
    let input_note_2 =
        input_token_2.create_random_input_token_note(&mut rng, alice_nk, &alice_auth);

    let input_token_3 = Token::new("xan".to_string(), 3u64);
    let input_note_3 =
        input_token_3.create_random_input_token_note(&mut rng, alice_nk, &alice_auth);
    let mut cascade_intent_note =
        create_intent_note(&mut rng, input_note_3.commitment().inner(), alice_nk);
    let output_token_2 = Token::new("eth".to_string(), 2u64);
    let mut output_note_2 = output_token_2.create_random_output_token_note(bob_nk_com, &bob_auth);
    let output_token_3 = Token::new("xan".to_string(), 3u64);
    let mut output_note_3 = output_token_3.create_random_output_token_note(bob_nk_com, &bob_auth);

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Fetch a valid anchor for dummy notes
    let anchor = Anchor::from(pallas::Base::random(&mut rng));

    // The first partial transaction:
    // Alice consumes 1 "BTC" and 2 "ETH".
    // Alice creates a cascade intent note and 1 "BTC" to Bob.
    let ptx_1 = {
        // Create action pairs
        let actions = {
            let action_1 = ActionInfo::new(
                *input_note_1.note(),
                merkle_path.clone(),
                None,
                &mut output_note_1.note,
                &mut rng,
            );

            let action_2 = ActionInfo::new(
                *input_note_2.note(),
                merkle_path.clone(),
                None,
                &mut cascade_intent_note,
                &mut rng,
            );
            vec![action_1, action_2]
        };

        // Create VPs
        let (input_vps, output_vps) = {
            let input_notes = [*input_note_1.note(), *input_note_2.note()];
            let output_notes = [*output_note_1.note(), cascade_intent_note];

            // Create the input note_1 vps
            let input_note_1_vps = input_note_1.generate_input_token_vps(
                &mut rng,
                alice_auth,
                alice_auth_sk,
                input_notes,
                output_notes,
            );

            // Create the input note_2 vps
            let input_note_2_vps = input_note_2.generate_input_token_vps(
                &mut rng,
                alice_auth,
                alice_auth_sk,
                input_notes,
                output_notes,
            );

            // Create the output note_1 vps
            let output_note_1_vps = output_note_1.generate_output_token_vps(
                &mut rng,
                bob_auth,
                input_notes,
                output_notes,
            );

            // Create intent vps
            let intent_vps = {
                let intent_vp = CascadeIntentValidityPredicateCircuit {
                    owned_note_pub_id: cascade_intent_note.commitment().inner(),
                    input_notes,
                    output_notes,
                    cascade_note_cm: cascade_intent_note.get_app_data_static(),
                };

                NoteValidityPredicates::new(Box::new(intent_vp), vec![])
            };

            (
                vec![input_note_1_vps, input_note_2_vps],
                vec![output_note_1_vps, intent_vps],
            )
        };

        // Create shielded partial tx
        ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng).unwrap()
    };

    // The second partial transaction:
    // Alice consumes the intent note and 3 "XAN";
    // Alice creates 2 "ETH" and 3 "XAN" to Bob
    let ptx_2 = {
        // Create action pairs
        let actions = {
            let action_1 = ActionInfo::new(
                cascade_intent_note,
                merkle_path.clone(),
                Some(anchor),
                &mut output_note_2.note,
                &mut rng,
            );

            let action_2 = ActionInfo::new(
                *input_note_3.note(),
                merkle_path,
                None,
                &mut output_note_3.note,
                &mut rng,
            );
            vec![action_1, action_2]
        };

        // Create VPs
        let (input_vps, output_vps) = {
            let input_notes = [cascade_intent_note, *input_note_3.note()];
            let output_notes = [*output_note_2.note(), *output_note_3.note()];

            // Create intent vps
            let intent_vps = {
                let intent_vp = CascadeIntentValidityPredicateCircuit {
                    owned_note_pub_id: cascade_intent_note.get_nf().unwrap().inner(),
                    input_notes,
                    output_notes,
                    cascade_note_cm: cascade_intent_note.get_app_data_static(),
                };

                NoteValidityPredicates::new(Box::new(intent_vp), vec![])
            };

            // Create input note_3 vps
            let input_note_3_vps = input_note_3.generate_input_token_vps(
                &mut rng,
                alice_auth,
                alice_auth_sk,
                input_notes,
                output_notes,
            );

            // Create output note_2 vps
            let output_note_2_vps = output_note_2.generate_output_token_vps(
                &mut rng,
                bob_auth,
                input_notes,
                output_notes,
            );

            // Create output note_3 vps
            let output_note_3_vps = output_note_3.generate_output_token_vps(
                &mut rng,
                bob_auth,
                input_notes,
                output_notes,
            );

            (
                vec![intent_vps, input_note_3_vps],
                vec![output_note_2_vps, output_note_3_vps],
            )
        };

        // Create shielded partial tx
        ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng).unwrap()
    };

    // Create the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::new(vec![ptx_1, ptx_2]);
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(&mut rng, shielded_tx_bundle, transparent_ptx_bundle).unwrap()
}

#[test]
fn test_cascade_ptxs() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_transaction(&mut rng);
    tx.execute().unwrap();
}
