/// Token swap example with intent note
/// Alice has 5 "BTC" and wants 1 "DOLPHIN" or 2 "Monkeys". Then Alice creates an intent for it.
/// Bob has 1 "DOLPHIN" and wants 5 "BTC".
/// The Solver/Bob matches Alice's intent and creates the final tx.
///
use crate::token::create_token_swap_ptx;
use group::Group;
use halo2_proofs::arithmetic::Field;
use pasta_curves::{group::Curve, pallas};
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    action::ActionInfo,
    circuit::vp_examples::{
        or_relation_intent::{create_intent_note, OrRelationIntentValidityPredicateCircuit},
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    note::{Note, NoteValidityPredicates},
    nullifier::{Nullifier, NullifierKeyContainer},
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};

pub fn create_token_intent_ptx<R: RngCore>(
    mut rng: R,
    token_1: Token,
    token_2: Token,
    input_token: Token,
    input_auth_sk: pallas::Scalar,
    input_nk: NullifierKeyContainer, // NullifierKeyContainer::Key
) -> (
    ShieldedPartialTransaction,
    NullifierKeyContainer,
    pallas::Base,
    pallas::Base,
    Nullifier,
) {
    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);

    // input note
    let rho = Nullifier::from(pallas::Base::random(&mut rng));
    let input_note = input_token.create_random_token_note(&mut rng, rho, input_nk, &input_auth);

    // output intent note
    let input_note_nf = input_note.get_nf().unwrap();
    let input_note_nk_com = input_note.get_nk_commitment();
    let intent_note = create_intent_note(
        &mut rng,
        &token_1,
        &token_2,
        input_note_nk_com,
        input_note.app_data_dynamic,
        input_note_nf,
        input_nk,
    );

    // padding the zero notes
    let padding_input_note = Note::random_padding_input_note(&mut rng);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::random_padding_output_note(&mut rng, padding_input_note_nf);

    let input_notes = [*input_note.note(), padding_input_note];
    let output_notes = [intent_note, padding_output_note];

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create action pairs
    let actions = {
        let action_1 = ActionInfo::new(
            *input_note.note(),
            merkle_path.clone(),
            None,
            intent_note,
            &mut rng,
        );

        // Fetch a valid anchor for padding input notes
        let anchor = Anchor::from(pallas::Base::random(&mut rng));
        let action_2 = ActionInfo::new(
            padding_input_note,
            merkle_path,
            Some(anchor),
            padding_output_note,
            &mut rng,
        );
        vec![action_1, action_2]
    };

    // Create VPs
    let (input_vps, output_vps) = {
        // Create the input note vps
        let input_note_vps = input_note.generate_input_token_vps(
            &mut rng,
            input_auth,
            input_auth_sk,
            input_notes,
            output_notes,
        );

        // Create the intent note proving info
        let intent_note_vps = {
            let intent_vp = OrRelationIntentValidityPredicateCircuit {
                owned_note_pub_id: intent_note.commitment().inner(),
                input_notes,
                output_notes,
                token_1,
                token_2,
                receiver_nk_com: input_note_nk_com,
                receiver_app_data_dynamic: input_note.app_data_dynamic,
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
            vec![input_note_vps, padding_input_vps],
            vec![intent_note_vps, padding_output_vps],
        )
    };

    // Create shielded partial tx
    let ptx = ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng)
        .unwrap();

    (
        ptx,
        input_nk,
        input_note_nk_com,
        input_note.app_data_dynamic,
        rho,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn consume_token_intent_ptx<R: RngCore>(
    mut rng: R,
    token_1: Token,
    token_2: Token,
    input_rho: Nullifier,
    input_nk: NullifierKeyContainer, // NullifierKeyContainer::Key
    receiver_nk_com: pallas::Base,
    receiver_app_data_dynamic: pallas::Base,
    output_token: Token,
    output_auth_pk: pallas::Point,
) -> ShieldedPartialTransaction {
    // input intent note
    let intent_note = create_intent_note(
        &mut rng,
        &token_1,
        &token_2,
        receiver_nk_com,
        receiver_app_data_dynamic,
        input_rho,
        input_nk,
    );

    // output note
    let input_note_nf = intent_note.get_nf().unwrap();
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
    let output_note = output_token.create_random_token_note(
        &mut rng,
        input_note_nf,
        input_nk.to_commitment(),
        &output_auth,
    );

    // padding the zero notes
    let padding_input_note = Note::random_padding_input_note(&mut rng);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::random_padding_output_note(&mut rng, padding_input_note_nf);

    let input_notes = [intent_note, padding_input_note];
    let output_notes = [*output_note.note(), padding_output_note];

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Fetch a valid anchor for dummy notes
    let anchor = Anchor::from(pallas::Base::random(&mut rng));

    // Create action pairs
    let actions = {
        let action_1 = ActionInfo::new(
            intent_note,
            merkle_path.clone(),
            Some(anchor),
            *output_note.note(),
            &mut rng,
        );

        let action_2 = ActionInfo::new(
            padding_input_note,
            merkle_path,
            Some(anchor),
            padding_output_note,
            &mut rng,
        );
        vec![action_1, action_2]
    };

    // Create VPs
    let (input_vps, output_vps) = {
        // Create intent vps
        let intent_vps = {
            let intent_vp = OrRelationIntentValidityPredicateCircuit {
                owned_note_pub_id: input_note_nf.inner(),
                input_notes,
                output_notes,
                token_1,
                token_2,
                receiver_nk_com,
                receiver_app_data_dynamic,
            };

            NoteValidityPredicates::new(Box::new(intent_vp), vec![])
        };

        // Create the output token vps
        let output_token_vps =
            output_note.generate_output_token_vps(&mut rng, output_auth, input_notes, output_notes);

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
            vec![intent_vps, padding_input_vps],
            vec![output_token_vps, padding_output_vps],
        )
    };

    // Create shielded partial tx
    ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng).unwrap()
}

pub fn create_token_swap_intent_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let generator = pallas::Point::generator().to_affine();

    // Alice creates the partial transaction with 5 BTC input and intent output
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth_pk = generator * alice_auth_sk;
    let alice_nk = NullifierKeyContainer::random_key(&mut rng);
    let token_1 = Token::new("dolphin".to_string(), 1u64);
    let token_2 = Token::new("monkey".to_string(), 2u64);
    let btc_token = Token::new("btc".to_string(), 5u64);
    let (alice_ptx, intent_nk, receiver_nk_com, receiver_app_data_dynamic, intent_rho) =
        create_token_intent_ptx(
            &mut rng,
            token_1.clone(),
            token_2.clone(),
            btc_token.clone(),
            alice_auth_sk,
            alice_nk,
        );

    // Bob creates the partial transaction with 1 DOLPHIN input and 5 BTC output
    let bob_auth_sk = pallas::Scalar::random(&mut rng);
    let bob_auth_pk = generator * bob_auth_sk;
    let bob_nk = NullifierKeyContainer::random_key(&mut rng);

    let bob_ptx = create_token_swap_ptx(
        &mut rng,
        token_1.clone(),
        bob_auth_sk,
        bob_nk,
        btc_token,
        bob_auth_pk,
        bob_nk.to_commitment(),
    );

    // Solver/Bob creates the partial transaction to consume the intent note
    // The bob_ptx and solver_ptx can be merged to one ptx.
    let solver_ptx = consume_token_intent_ptx(
        &mut rng,
        token_1.clone(),
        token_2,
        intent_rho,
        intent_nk,
        receiver_nk_com,
        receiver_app_data_dynamic,
        token_1,
        alice_auth_pk,
    );

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::new(vec![alice_ptx, bob_ptx, solver_ptx]);
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(&mut rng, shielded_tx_bundle, transparent_ptx_bundle)
}

#[test]
fn test_token_swap_intent_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_intent_transaction(&mut rng);
    tx.execute().unwrap();
}
