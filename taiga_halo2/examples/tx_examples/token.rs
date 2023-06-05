use halo2_proofs::arithmetic::Field;

use pasta_curves::pallas;
use rand::RngCore;

use taiga_halo2::{
    circuit::vp_examples::{
        signature_verification::TOKEN_AUTH_VK,
        token::{
            generate_input_token_note_proving_info, generate_output_token_note_proving_info,
            transfrom_token_name_to_token_property, TokenAuthorization, TOKEN_VK,
        },
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteProvingInfo, Note, OutputNoteProvingInfo},
    nullifier::{Nullifier, NullifierDerivingKey, NullifierKeyCom},
    shielded_ptx::ShieldedPartialTransaction,
};

pub fn create_random_token_note<R: RngCore>(
    mut rng: R,
    name: &str,
    value: u64,
    rho: Nullifier,
    nk_com: NullifierKeyCom,
    auth: &TokenAuthorization,
) -> Note {
    let app_data_static = transfrom_token_name_to_token_property(name);
    let app_data_dynamic = auth.to_app_data_dynamic();
    let rcm = pallas::Scalar::random(&mut rng);
    let psi = pallas::Base::random(&mut rng);
    Note::new(
        TOKEN_VK.clone(),
        app_data_static,
        app_data_dynamic,
        value,
        nk_com,
        rho,
        psi,
        rcm,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_token_swap_ptx<R: RngCore>(
    mut rng: R,
    input_token: &str,
    input_value: u64,
    input_auth_sk: pallas::Scalar,
    input_nk: NullifierDerivingKey, // NullifierKeyCom::Open
    output_token: &str,
    output_value: u64,
    output_auth_pk: pallas::Point,
    output_nk_com: pallas::Base, // NullifierKeyCom::Closed
) -> (ShieldedPartialTransaction, pallas::Scalar) {
    let compressed_auth_vk = TOKEN_AUTH_VK.get_compressed();

    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &compressed_auth_vk);

    // input note
    let rho = Nullifier::new(pallas::Base::random(&mut rng));
    let input_nk_com = NullifierKeyCom::from_open(input_nk);
    let input_note = create_random_token_note(
        &mut rng,
        input_token,
        input_value,
        rho,
        input_nk_com,
        &input_auth,
    );

    // output note
    let input_note_nf = input_note.get_nf().unwrap();
    let output_auth = TokenAuthorization::new(output_auth_pk, compressed_auth_vk);
    let output_nk_com = NullifierKeyCom::from_closed(output_nk_com);
    let output_note = create_random_token_note(
        &mut rng,
        output_token,
        output_value,
        input_note_nf,
        output_nk_com,
        &output_auth,
    );

    // padding the zero notes
    let padding_input_note = Note::dummy_zero_note(&mut rng, rho);
    let padding_input_note_nf = padding_input_note.get_nf().unwrap();
    let padding_output_note = Note::dummy_zero_note(&mut rng, padding_input_note_nf);

    let input_notes = [input_note.clone(), padding_input_note.clone()];
    let output_notes = [output_note.clone(), padding_output_note.clone()];

    // Generate proving info
    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create the input note proving info
    let input_note_proving_info = generate_input_token_note_proving_info(
        &mut rng,
        input_note,
        input_token.to_string(),
        input_auth,
        input_auth_sk,
        merkle_path.clone(),
        input_notes.clone(),
        output_notes.clone(),
    );

    // Create the output note proving info
    let output_note_proving_info = generate_output_token_note_proving_info(
        output_note,
        output_token.to_string(),
        output_auth,
        input_notes.clone(),
        output_notes.clone(),
    );

    // Create the padding input note proving info
    let padding_input_note_proving_info = InputNoteProvingInfo::create_padding_note_proving_info(
        padding_input_note,
        merkle_path,
        input_notes.clone(),
        output_notes.clone(),
    );

    // Create the padding output note proving info
    let padding_output_note_proving_info = OutputNoteProvingInfo::create_padding_note_proving_info(
        padding_output_note,
        input_notes,
        output_notes,
    );

    // Create shielded partial tx
    ShieldedPartialTransaction::build(
        [input_note_proving_info, padding_input_note_proving_info],
        [output_note_proving_info, padding_output_note_proving_info],
        &mut rng,
    )
}