/// Multi-party token swap without intent notes
/// Alice has 5 input_token and wants 10 "ETH"
/// Bob has 10 "ETH" and wants 15 "XAN"
/// Carol has 15 "XAN" and wants 5 BTC""
///
use crate::token::{create_random_token_note, TOKEN_AUTH_VK};
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    circuit::vp_examples::{
        signature_verification::SignatureVerificationValidityPredicateCircuit,
        token::{TokenAuthorization, TokenValidityPredicateCircuit},
        TrivialValidityPredicateCircuit,
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteInfo, Note, OutputNoteInfo},
    nullifier::Nullifier,
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction},
};

fn create_token_swap_ptx<R: RngCore>(
    mut rng: R,
    input_token: &str,
    input_value: u64,
    output_toke: &str,
    output_value: u64,
) -> (ShieldedPartialTransaction, pallas::Scalar) {
    let compressed_auth_vk = TOKEN_AUTH_VK.get_compressed();

    // auth_sk is to generate the signaure to authorize the note spending
    let auth_sk = pallas::Scalar::random(&mut rng);
    let auth = TokenAuthorization::from_sk_vk(&auth_sk, &compressed_auth_vk);

    // input note
    let rho = Nullifier::new(pallas::Base::random(&mut rng));
    let inpute_note = create_random_token_note(&mut rng, input_token, input_value, rho, &auth);

    // output note
    let input_note_nf = inpute_note.get_nf().unwrap();
    let output_note =
        create_random_token_note(&mut rng, output_toke, output_value, input_note_nf, &auth);

    // padding the zero notes
    let padding_input_note = Note::dummy_zero_note(&mut rng, rho);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::dummy_zero_note(&mut rng, padding_input_note_nf);

    // Generate proving info
    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create the input note proving info
    let input_note_proving_info = {
        // input note token VP
        let token_vp = Box::new(TokenValidityPredicateCircuit {
            owned_note_pub_id: input_note_nf.inner(),
            input_notes: [inpute_note.clone(), padding_input_note.clone()],
            output_notes: [output_note.clone(), padding_output_note.clone()],
            token_name: input_token.to_string(),
            auth,
        });

        // token auth VP
        let token_auth_vp = Box::new(
            SignatureVerificationValidityPredicateCircuit::from_sk_and_sign(
                &mut rng,
                input_note_nf.inner(),
                [inpute_note.clone(), padding_input_note.clone()],
                [output_note.clone(), padding_output_note.clone()],
                compressed_auth_vk,
                auth_sk,
            ),
        );

        // inpute note proving info
        InputNoteInfo::new(
            inpute_note.clone(),
            merkle_path.clone(),
            token_vp,
            vec![token_auth_vp],
        )
    };

    // Create the output note proving info
    let output_note_proving_info = {
        // token VP
        let token_vp = Box::new(TokenValidityPredicateCircuit {
            owned_note_pub_id: output_note.commitment().get_x(),
            input_notes: [inpute_note.clone(), padding_input_note.clone()],
            output_notes: [output_note.clone(), padding_output_note.clone()],
            token_name: output_toke.to_string(),
            auth,
        });

        OutputNoteInfo::new(output_note.clone(), token_vp, vec![])
    };

    // Create the padding input note proving info
    let padding_input_note_proving_info = {
        let trivail_vp = Box::new(TrivialValidityPredicateCircuit {
            owned_note_pub_id: padding_input_note_nf.inner(),
            input_notes: [inpute_note.clone(), padding_input_note.clone()],
            output_notes: [output_note.clone(), padding_output_note.clone()],
        });
        InputNoteInfo::new(padding_input_note.clone(), merkle_path, trivail_vp, vec![])
    };

    // Create the padding output note proving info
    let padding_output_note_proving_info = {
        let trivail_vp = Box::new(TrivialValidityPredicateCircuit {
            owned_note_pub_id: padding_output_note.commitment().get_x(),
            input_notes: [inpute_note, padding_input_note],
            output_notes: [output_note, padding_output_note.clone()],
        });
        OutputNoteInfo::new(padding_output_note, trivail_vp, vec![])
    };

    // Create shielded partial tx
    ShieldedPartialTransaction::build(
        [input_note_proving_info, padding_input_note_proving_info],
        [output_note_proving_info, padding_output_note_proving_info],
        &mut rng,
    )
}

pub fn create_token_swap_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    // Alice creates the partial transaction
    let (alice_ptx, alice_r) = create_token_swap_ptx(&mut rng, "btc", 5, "eth", 10);

    // Bob creates the partial transaction
    let (bob_ptx, bob_r) = create_token_swap_ptx(&mut rng, "eth", 10, "xan", 15);

    // Carol creates the partial transaction
    let (carol_ptx, carol_r) = create_token_swap_ptx(&mut rng, "xan", 15, "btc", 5);

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::build(vec![alice_ptx, bob_ptx, carol_ptx]);
    let mut tx = Transaction::new(
        Some(shielded_tx_bundle),
        None,
        vec![alice_r, bob_r, carol_r],
    );
    tx.binding_sign(rng);
    tx
}

#[test]
fn test_basic_swap_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_transaction(&mut rng);
    tx.execute().unwrap();
}
