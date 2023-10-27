use halo2_proofs::arithmetic::Field;

use pasta_curves::pallas;
use rand::RngCore;

use taiga_halo2::{
    action::ActionInfo,
    circuit::vp_examples::{
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    note::{Note, NoteValidityPredicates, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
    shielded_ptx::ShieldedPartialTransaction,
};

#[allow(clippy::too_many_arguments)]
pub fn create_token_swap_ptx<R: RngCore>(
    mut rng: R,
    input_token: Token,
    input_auth_sk: pallas::Scalar,
    input_nk: NullifierKeyContainer, // NullifierKeyContainer::Key
    output_token: Token,
    output_auth_pk: pallas::Point,
    output_nk_com: NullifierKeyContainer, // NullifierKeyContainer::Commitment
) -> ShieldedPartialTransaction {
    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);

    // input note
    let rho = Nullifier::from(pallas::Base::random(&mut rng));
    let input_note = input_token.create_random_token_note(&mut rng, rho, input_nk, &input_auth);

    // output note
    let input_note_nf = input_note.get_nf().unwrap();
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
    let output_note =
        output_token.create_random_token_note(&mut rng, input_note_nf, output_nk_com, &output_auth);

    // padding the zero notes
    let padding_input_note = Note::random_padding_input_note(&mut rng);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::random_padding_output_note(&mut rng, padding_input_note_nf);

    let input_notes = [*input_note.note(), padding_input_note];
    let output_notes = [*output_note.note(), padding_output_note];

    // Generate proving info
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create action pairs
    let actions = {
        let rseed_1 = RandomSeed::random(&mut rng);
        let anchor_1 = input_note.calculate_root(&merkle_path);
        let action_1 = ActionInfo::new(
            *input_note.note(),
            merkle_path.clone(),
            anchor_1,
            *output_note.note(),
            rseed_1,
        );

        // Fetch a valid anchor for padding input notes
        let anchor_2 = Anchor::from(pallas::Base::random(&mut rng));
        let rseed_2 = RandomSeed::random(&mut rng);
        let action_2 = ActionInfo::new(
            padding_input_note,
            merkle_path,
            anchor_2,
            padding_output_note,
            rseed_2,
        );
        vec![action_1, action_2]
    };

    // Create VPs
    let (input_vps, output_vps) = {
        // Create the input token vps
        let input_token_vps = input_note.generate_input_token_vps(
            &mut rng,
            input_auth,
            input_auth_sk,
            input_notes,
            output_notes,
        );

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
            vec![input_token_vps, padding_input_vps],
            vec![output_token_vps, padding_output_vps],
        )
    };

    // Create shielded partial tx
    ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng).unwrap()
}
