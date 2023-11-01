/// The token swap intent can be partially fulfilled.
/// Alice has 2 "BTC" and wants 10 "ETH". Then Alice creates an intent for it.
/// Bob has 5 "ETH" and wants 1 "BTC".
/// The Solver/Bob can partially fulfill Alice's intent and return 1 "BTC" back to Alice.
///
use crate::token::create_token_swap_ptx;
use group::Group;
use halo2_proofs::arithmetic::Field;
use pasta_curves::{group::Curve, pallas};
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    action::ActionInfo,
    circuit::vp_examples::{
        partial_fulfillment_intent::{PartialFulfillmentIntentValidityPredicateCircuit, Swap},
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization, TokenNote},
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    note::{Note, NoteValidityPredicates},
    nullifier::NullifierKeyContainer,
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};

pub fn create_token_intent_ptx<R: RngCore>(
    mut rng: R,
    sell: Token,
    buy: Token,
    input_auth_sk: pallas::Scalar,
) -> (ShieldedPartialTransaction, Swap, Note) {
    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);
    let swap = Swap::random(&mut rng, sell, buy, input_auth);
    let mut intent_note = swap.create_intent_note(&mut rng);

    // padding the zero notes
    let padding_input_note = Note::random_padding_input_note(&mut rng);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let mut padding_output_note = Note::random_padding_output_note(&mut rng, padding_input_note_nf);
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create action pairs
    let actions = {
        let action_1 = ActionInfo::new(
            *swap.sell.note(),
            merkle_path.clone(),
            None,
            &mut intent_note,
            &mut rng,
        );

        // Fetch a valid anchor for dummy notes
        let anchor = Anchor::from(pallas::Base::random(&mut rng));
        let action_2 = ActionInfo::new(
            padding_input_note,
            merkle_path,
            Some(anchor),
            &mut padding_output_note,
            &mut rng,
        );
        vec![action_1, action_2]
    };

    // Create VPs
    let (input_vps, output_vps) = {
        let input_notes = [*swap.sell.note(), padding_input_note];
        let output_notes = [intent_note, padding_output_note];
        // Create the input token vps
        let input_token_vps = swap.sell.generate_input_token_vps(
            &mut rng,
            input_auth,
            input_auth_sk,
            input_notes,
            output_notes,
        );

        // Create the intent vps
        let intent_vps = {
            let intent_vp = PartialFulfillmentIntentValidityPredicateCircuit {
                owned_note_pub_id: intent_note.commitment().inner(),
                input_notes,
                output_notes,
                swap: swap.clone(),
            };

            NoteValidityPredicates::new(Box::new(intent_vp), vec![])
        };

        // Create the padding input vps
        let padding_input_vps = NoteValidityPredicates::create_input_padding_note_vps(
            &padding_input_note,
            input_notes,
            output_notes,
        );

        // Create the padding output vps
        let padding_output_vps = NoteValidityPredicates::create_output_padding_note_vps(
            &padding_output_note,
            input_notes,
            output_notes,
        );

        (
            vec![input_token_vps, padding_input_vps],
            vec![intent_vps, padding_output_vps],
        )
    };

    // Create shielded partial tx
    let ptx = ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng)
        .unwrap();

    (ptx, swap, intent_note)
}

#[allow(clippy::too_many_arguments)]
pub fn consume_token_intent_ptx<R: RngCore>(
    mut rng: R,
    swap: Swap,
    intent_note: Note,
    offer: Token,
    output_auth_pk: pallas::Point,
) -> ShieldedPartialTransaction {
    let (input_notes, [mut bought_note, mut returned_note]) =
        swap.fill(&mut rng, intent_note, offer);
    let [intent_note, padding_input_note] = input_notes;

    // output notes
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Fetch a valid anchor for dummy notes
    let anchor = Anchor::from(pallas::Base::random(&mut rng));

    // Create action pairs
    let actions = {
        let action_1 = ActionInfo::new(
            intent_note,
            merkle_path.clone(),
            Some(anchor),
            &mut bought_note,
            &mut rng,
        );

        let action_2 = ActionInfo::new(
            padding_input_note,
            merkle_path,
            Some(anchor),
            &mut returned_note,
            &mut rng,
        );
        vec![action_1, action_2]
    };

    // Create VPs
    let (input_vps, output_vps) = {
        let output_notes = [bought_note, returned_note];
        // Create intent vps
        let intent_vps = {
            let intent_vp = PartialFulfillmentIntentValidityPredicateCircuit {
                owned_note_pub_id: intent_note.get_nf().unwrap().inner(),
                input_notes,
                output_notes,
                swap: swap.clone(),
            };

            NoteValidityPredicates::new(Box::new(intent_vp), vec![])
        };

        // Create bought_note_vps
        let bought_note_vps = TokenNote {
            token_name: swap.buy.name().clone(),
            note: bought_note,
        }
        .generate_output_token_vps(&mut rng, output_auth, input_notes, output_notes);

        // Create the padding input vps
        let padding_input_vps = NoteValidityPredicates::create_input_padding_note_vps(
            &padding_input_note,
            input_notes,
            output_notes,
        );

        // Create returned_note_vps
        let returned_note_vps = TokenNote {
            token_name: swap.sell.token_name().clone(),
            note: returned_note,
        }
        .generate_output_token_vps(&mut rng, output_auth, input_notes, output_notes);

        (
            vec![intent_vps, padding_input_vps],
            vec![bought_note_vps, returned_note_vps],
        )
    };

    // Create shielded partial tx
    ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng).unwrap()
}

pub fn create_token_swap_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let generator = pallas::Point::generator().to_affine();

    // Alice creates the partial transaction with:
    // - 2 BTC sell
    // - intent output encoding 10 ETH ask
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth_pk = generator * alice_auth_sk;
    let sell = Token::new("btc".to_string(), 2u64);
    let buy = Token::new("eth".to_string(), 10u64);
    let (alice_ptx, swap, intent_note) =
        create_token_intent_ptx(&mut rng, sell.clone(), buy.clone(), alice_auth_sk);

    // Bob creates the partial transaction with 1 DOLPHIN input and 5 BTC output
    let bob_auth_sk = pallas::Scalar::random(&mut rng);
    let bob_auth_pk = generator * bob_auth_sk;
    let bob_nk = NullifierKeyContainer::random_key(&mut rng);
    let offer = Token::new("eth".to_string(), 5);
    let returned = Token::new("btc".to_string(), 1);

    let bob_ptx = create_token_swap_ptx(
        &mut rng,
        offer.clone(),
        bob_auth_sk,
        bob_nk.get_nk().unwrap(),
        returned,
        bob_auth_pk,
        bob_nk.get_commitment(),
    );

    // Solver/Bob creates the partial transaction to consume the intent note
    // The bob_ptx and solver_ptx can be merged to one ptx.
    let solver_ptx = consume_token_intent_ptx(&mut rng, swap, intent_note, offer, alice_auth_pk);

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::new(vec![alice_ptx, bob_ptx, solver_ptx]);
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(&mut rng, shielded_tx_bundle, transparent_ptx_bundle)
}

#[test]
fn test_partial_fulfillment_token_swap_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_transaction(&mut rng);
    tx.execute().unwrap();
}
