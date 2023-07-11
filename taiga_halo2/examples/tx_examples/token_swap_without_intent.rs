/// Multi-party token swap without intent notes
/// Alice has 5 "BTC" and wants 10 "ETH"
/// Bob has 10 "ETH" and wants 15 "XAN"
/// Carol has 15 "XAN" and wants 5 BTC""
///
use crate::token::create_token_swap_ptx;
use group::Group;
use halo2_proofs::arithmetic::Field;
use pasta_curves::{group::Curve, pallas};
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    nullifier::NullifierKey,
    transaction::{ShieldedPartialTxBundle, Transaction},
};

pub fn create_token_swap_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let generator = pallas::Point::generator().to_affine();

    // Alice creates the partial transaction
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth_pk = generator * alice_auth_sk;
    let alice_nk = NullifierKey::random(&mut rng);

    let (alice_ptx, alice_r) = create_token_swap_ptx(
        &mut rng,
        "btc",
        5,
        alice_auth_sk,
        alice_nk,
        "eth",
        10,
        alice_auth_pk,
        alice_nk,
    );

    // Bob creates the partial transaction
    let bob_auth_sk = pallas::Scalar::random(&mut rng);
    let bob_auth_pk = generator * bob_auth_sk;
    let bob_nk = NullifierKey::random(&mut rng);

    let (bob_ptx, bob_r) = create_token_swap_ptx(
        &mut rng,
        "eth",
        10,
        bob_auth_sk,
        bob_nk,
        "xan",
        15,
        bob_auth_pk,
        bob_nk,
    );

    // Carol creates the partial transaction
    let carol_auth_sk = pallas::Scalar::random(&mut rng);
    let carol_auth_pk = generator * carol_auth_sk;
    let carol_nk = NullifierKey::random(&mut rng);

    let (carol_ptx, carol_r) = create_token_swap_ptx(
        &mut rng,
        "xan",
        15,
        carol_auth_sk,
        carol_nk,
        "btc",
        5,
        carol_auth_pk,
        carol_nk,
    );

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::build(vec![alice_ptx, bob_ptx, carol_ptx]);
    Transaction::build(
        &mut rng,
        Some(shielded_tx_bundle),
        None,
        vec![alice_r, bob_r, carol_r],
    )
}

#[test]
fn test_basic_swap_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_transaction(&mut rng);
    tx.execute().unwrap();
}
