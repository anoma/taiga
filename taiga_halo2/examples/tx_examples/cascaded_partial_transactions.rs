/// The example shows how to cascade the partial transactions by intents.
/// Alice wants to spend 1 "BTC", 2 "ETH" and 3 "XAN" simultaneously
///
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    action::ActionInfo,
    circuit::vp_examples::{
        cascade_intent::{create_intent_resource, CascadeIntentValidityPredicateCircuit},
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    resource::ResourceValidityPredicates,
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
    let input_resource_1 =
        input_token_1.create_random_input_token_resource(&mut rng, alice_nk, &alice_auth);
    let output_token_1 = Token::new("btc".to_string(), 1u64);
    let mut output_resource_1 =
        output_token_1.create_random_output_token_resource(bob_nk_com, &bob_auth);
    let input_token_2 = Token::new("eth".to_string(), 2u64);
    let input_resource_2 =
        input_token_2.create_random_input_token_resource(&mut rng, alice_nk, &alice_auth);

    let input_token_3 = Token::new("xan".to_string(), 3u64);
    let input_resource_3 =
        input_token_3.create_random_input_token_resource(&mut rng, alice_nk, &alice_auth);
    let mut cascade_intent_resource =
        create_intent_resource(&mut rng, input_resource_3.commitment().inner(), alice_nk);
    let output_token_2 = Token::new("eth".to_string(), 2u64);
    let mut output_resource_2 =
        output_token_2.create_random_output_token_resource(bob_nk_com, &bob_auth);
    let output_token_3 = Token::new("xan".to_string(), 3u64);
    let mut output_resource_3 =
        output_token_3.create_random_output_token_resource(bob_nk_com, &bob_auth);

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Fetch a valid anchor for dummy resources
    let anchor = Anchor::from(pallas::Base::random(&mut rng));

    // The first partial transaction:
    // Alice consumes 1 "BTC" and 2 "ETH".
    // Alice creates a cascade intent resource and 1 "BTC" to Bob.
    let ptx_1 = {
        // Create action pairs
        let actions = {
            let action_1 = ActionInfo::new(
                *input_resource_1.resource(),
                merkle_path.clone(),
                None,
                &mut output_resource_1.resource,
                &mut rng,
            );

            let action_2 = ActionInfo::new(
                *input_resource_2.resource(),
                merkle_path.clone(),
                None,
                &mut cascade_intent_resource,
                &mut rng,
            );
            vec![action_1, action_2]
        };

        // Create VPs
        let (input_vps, output_vps) = {
            let input_resources = [*input_resource_1.resource(), *input_resource_2.resource()];
            let output_resources = [*output_resource_1.resource(), cascade_intent_resource];

            // Create the input resource_1 vps
            let input_resource_1_vps = input_resource_1.generate_input_token_vps(
                &mut rng,
                alice_auth,
                alice_auth_sk,
                input_resources,
                output_resources,
            );

            // Create the input resource_2 vps
            let input_resource_2_vps = input_resource_2.generate_input_token_vps(
                &mut rng,
                alice_auth,
                alice_auth_sk,
                input_resources,
                output_resources,
            );

            // Create the output resource_1 vps
            let output_resource_1_vps = output_resource_1.generate_output_token_vps(
                &mut rng,
                bob_auth,
                input_resources,
                output_resources,
            );

            // Create intent vps
            let intent_vps = {
                let intent_vp = CascadeIntentValidityPredicateCircuit {
                    owned_resource_id: cascade_intent_resource.commitment().inner(),
                    input_resources,
                    output_resources,
                    cascade_resource_cm: cascade_intent_resource.get_label(),
                };

                ResourceValidityPredicates::new(Box::new(intent_vp), vec![])
            };

            (
                vec![input_resource_1_vps, input_resource_2_vps],
                vec![output_resource_1_vps, intent_vps],
            )
        };

        // Create shielded partial tx
        ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng).unwrap()
    };

    // The second partial transaction:
    // Alice consumes the intent resource and 3 "XAN";
    // Alice creates 2 "ETH" and 3 "XAN" to Bob
    let ptx_2 = {
        // Create action pairs
        let actions = {
            let action_1 = ActionInfo::new(
                cascade_intent_resource,
                merkle_path.clone(),
                Some(anchor),
                &mut output_resource_2.resource,
                &mut rng,
            );

            let action_2 = ActionInfo::new(
                *input_resource_3.resource(),
                merkle_path,
                None,
                &mut output_resource_3.resource,
                &mut rng,
            );
            vec![action_1, action_2]
        };

        // Create VPs
        let (input_vps, output_vps) = {
            let input_resources = [cascade_intent_resource, *input_resource_3.resource()];
            let output_resources = [*output_resource_2.resource(), *output_resource_3.resource()];

            // Create intent vps
            let intent_vps = {
                let intent_vp = CascadeIntentValidityPredicateCircuit {
                    owned_resource_id: cascade_intent_resource.get_nf().unwrap().inner(),
                    input_resources,
                    output_resources,
                    cascade_resource_cm: cascade_intent_resource.get_label(),
                };

                ResourceValidityPredicates::new(Box::new(intent_vp), vec![])
            };

            // Create input resource_3 vps
            let input_resource_3_vps = input_resource_3.generate_input_token_vps(
                &mut rng,
                alice_auth,
                alice_auth_sk,
                input_resources,
                output_resources,
            );

            // Create output resource_2 vps
            let output_resource_2_vps = output_resource_2.generate_output_token_vps(
                &mut rng,
                bob_auth,
                input_resources,
                output_resources,
            );

            // Create output resource_3 vps
            let output_resource_3_vps = output_resource_3.generate_output_token_vps(
                &mut rng,
                bob_auth,
                input_resources,
                output_resources,
            );

            (
                vec![intent_vps, input_resource_3_vps],
                vec![output_resource_2_vps, output_resource_3_vps],
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
