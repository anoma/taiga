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
    nullifier::NullifierKeyContainer,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};

pub fn create_token_swap_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let generator = pallas::Point::generator().to_affine();

    // Alice creates the partial transaction
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth_pk = generator * alice_auth_sk;
    let alice_nk = NullifierKeyContainer::random_key(&mut rng);

    let alice_ptx = create_token_swap_ptx(
        &mut rng,
        "btc",
        5,
        alice_auth_sk,
        alice_nk,
        "eth",
        10,
        alice_auth_pk,
        alice_nk.to_commitment(),
    );

    // Bob creates the partial transaction
    let bob_auth_sk = pallas::Scalar::random(&mut rng);
    let bob_auth_pk = generator * bob_auth_sk;
    let bob_nk = NullifierKeyContainer::random_key(&mut rng);

    let bob_ptx = create_token_swap_ptx(
        &mut rng,
        "eth",
        10,
        bob_auth_sk,
        bob_nk,
        "xan",
        15,
        bob_auth_pk,
        bob_nk.to_commitment(),
    );

    // Carol creates the partial transaction
    let carol_auth_sk = pallas::Scalar::random(&mut rng);
    let carol_auth_pk = generator * carol_auth_sk;
    let carol_nk = NullifierKeyContainer::random_key(&mut rng);

    let carol_ptx = create_token_swap_ptx(
        &mut rng,
        "xan",
        15,
        carol_auth_sk,
        carol_nk,
        "btc",
        5,
        carol_auth_pk,
        carol_nk.to_commitment(),
    );

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::build(vec![alice_ptx, bob_ptx, carol_ptx]);
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(&mut rng, shielded_tx_bundle, transparent_ptx_bundle)
}

#[test]
fn test_basic_swap_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_transaction(&mut rng);
    tx.execute().unwrap();
}
