use halo2_proofs::arithmetic::Field;

use pasta_curves::pallas;
use rand::RngCore;

use taiga_halo2::{
    circuit::vp_examples::{
        signature_verification::{SignatureVerificationValidityPredicateCircuit, TOKEN_AUTH_VK},
        token::{
            transfrom_token_name_to_token_property, TokenAuthorization,
            TokenValidityPredicateCircuit, TOKEN_VK,
        },
        TrivialValidityPredicateCircuit,
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteInfo, Note, OutputNoteInfo},
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
    let inpute_note = create_random_token_note(
        &mut rng,
        input_token,
        input_value,
        rho,
        input_nk_com,
        &input_auth,
    );

    // output note
    let input_note_nf = inpute_note.get_nf().unwrap();
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

    // Generate proving info
    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create the input note proving info
    let input_note_proving_info = {
        // input note token VP
        let token_vp = TokenValidityPredicateCircuit {
            owned_note_pub_id: input_note_nf.inner(),
            input_notes: [inpute_note.clone(), padding_input_note.clone()],
            output_notes: [output_note.clone(), padding_output_note.clone()],
            token_name: input_token.to_string(),
            auth: input_auth,
        };

        // token auth VP
        let token_auth_vp = SignatureVerificationValidityPredicateCircuit::from_sk_and_sign(
            &mut rng,
            input_note_nf.inner(),
            [inpute_note.clone(), padding_input_note.clone()],
            [output_note.clone(), padding_output_note.clone()],
            compressed_auth_vk,
            input_auth_sk,
        );

        // inpute note proving info
        InputNoteInfo::new(
            inpute_note.clone(),
            merkle_path.clone(),
            Box::new(token_vp),
            vec![Box::new(token_auth_vp)],
        )
    };

    // Create the output note proving info
    let output_note_proving_info = {
        // token VP
        let token_vp = TokenValidityPredicateCircuit {
            owned_note_pub_id: output_note.commitment().get_x(),
            input_notes: [inpute_note.clone(), padding_input_note.clone()],
            output_notes: [output_note.clone(), padding_output_note.clone()],
            token_name: output_token.to_string(),
            auth: output_auth,
        };

        OutputNoteInfo::new(output_note.clone(), Box::new(token_vp), vec![])
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
