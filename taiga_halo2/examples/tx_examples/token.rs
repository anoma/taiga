use halo2_proofs::arithmetic::Field;
use lazy_static::lazy_static;
use pasta_curves::pallas;
use rand::RngCore;
use taiga_halo2::{
    circuit::{
        vp_circuit::ValidityPredicateVerifyingInfo,
        vp_examples::{
            signature_verification::SignatureVerificationValidityPredicateCircuit,
            token::{
                transfrom_token_name_to_token_property, TokenAuthorization,
                TokenValidityPredicateCircuit,
            },
        },
    },
    note::Note,
    nullifier::{Nullifier, NullifierKeyCom},
    vp_vk::ValidityPredicateVerifyingKey,
};

lazy_static! {
    pub(crate) static ref TOKEN_VK: ValidityPredicateVerifyingKey =
        TokenValidityPredicateCircuit::default().get_vp_vk();
    pub(crate) static ref TOKEN_AUTH_VK: ValidityPredicateVerifyingKey =
        SignatureVerificationValidityPredicateCircuit::default().get_vp_vk();
}

pub fn create_random_token_note<R: RngCore>(
    mut rng: R,
    name: &str,
    value: u64,
    rho: Nullifier,
    auth: &TokenAuthorization,
) -> Note {
    let app_data_static = transfrom_token_name_to_token_property(name);
    let app_data_dynamic = auth.to_app_data_dynamic();
    let nk_com = NullifierKeyCom::rand(&mut rng);
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
