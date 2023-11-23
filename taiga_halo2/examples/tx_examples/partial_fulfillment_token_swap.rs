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
        token::{Token, TokenAuthorization, TokenResource},
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    nullifier::NullifierKeyContainer,
    resource::{Resource, ResourceValidityPredicates},
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};

pub fn create_token_intent_ptx<R: RngCore>(
    mut rng: R,
    sell: Token,
    buy: Token,
    input_auth_sk: pallas::Scalar,
) -> (ShieldedPartialTransaction, Swap, Resource) {
    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);
    let swap = Swap::random(&mut rng, sell, buy, input_auth);
    let mut intent_resource = swap.create_intent_resource(&mut rng);

    // padding the zero resources
    let padding_input_resource = Resource::random_padding_resource(&mut rng);
    let mut padding_output_resource = Resource::random_padding_resource(&mut rng);
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create action pairs
    let actions = {
        let action_1 = ActionInfo::new(
            *swap.sell.resource(),
            merkle_path.clone(),
            None,
            &mut intent_resource,
            &mut rng,
        );

        // Fetch a valid anchor for dummy resources
        let anchor = Anchor::from(pallas::Base::random(&mut rng));
        let action_2 = ActionInfo::new(
            padding_input_resource,
            merkle_path,
            Some(anchor),
            &mut padding_output_resource,
            &mut rng,
        );
        vec![action_1, action_2]
    };

    // Create VPs
    let (input_vps, output_vps) = {
        let input_resources = [*swap.sell.resource(), padding_input_resource];
        let output_resources = [intent_resource, padding_output_resource];
        // Create the input token vps
        let input_token_vps = swap.sell.generate_input_token_vps(
            &mut rng,
            input_auth,
            input_auth_sk,
            input_resources,
            output_resources,
        );

        // Create the intent vps
        let intent_vps = {
            let intent_vp = PartialFulfillmentIntentValidityPredicateCircuit {
                owned_resource_id: intent_resource.commitment().inner(),
                input_resources,
                output_resources,
                swap: swap.clone(),
            };

            ResourceValidityPredicates::new(Box::new(intent_vp), vec![])
        };

        // Create the padding input vps
        let padding_input_vps = ResourceValidityPredicates::create_input_padding_resource_vps(
            &padding_input_resource,
            input_resources,
            output_resources,
        );

        // Create the padding output vps
        let padding_output_vps = ResourceValidityPredicates::create_output_padding_resource_vps(
            &padding_output_resource,
            input_resources,
            output_resources,
        );

        (
            vec![input_token_vps, padding_input_vps],
            vec![intent_vps, padding_output_vps],
        )
    };

    // Create shielded partial tx
    let ptx = ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng)
        .unwrap();

    (ptx, swap, intent_resource)
}

#[allow(clippy::too_many_arguments)]
pub fn consume_token_intent_ptx<R: RngCore>(
    mut rng: R,
    swap: Swap,
    intent_resource: Resource,
    offer: Token,
    output_auth_pk: pallas::Point,
) -> ShieldedPartialTransaction {
    let (input_resources, [mut bought_resource, mut returned_resource]) =
        swap.fill(&mut rng, intent_resource, offer);
    let [intent_resource, padding_input_resource] = input_resources;

    // output resources
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Fetch a valid anchor for dummy resources
    let anchor = Anchor::from(pallas::Base::random(&mut rng));

    // Create action pairs
    let actions = {
        let action_1 = ActionInfo::new(
            intent_resource,
            merkle_path.clone(),
            Some(anchor),
            &mut bought_resource,
            &mut rng,
        );

        let action_2 = ActionInfo::new(
            padding_input_resource,
            merkle_path,
            Some(anchor),
            &mut returned_resource,
            &mut rng,
        );
        vec![action_1, action_2]
    };

    // Create VPs
    let (input_vps, output_vps) = {
        let output_resources = [bought_resource, returned_resource];
        // Create intent vps
        let intent_vps = {
            let intent_vp = PartialFulfillmentIntentValidityPredicateCircuit {
                owned_resource_id: intent_resource.get_nf().unwrap().inner(),
                input_resources,
                output_resources,
                swap: swap.clone(),
            };

            ResourceValidityPredicates::new(Box::new(intent_vp), vec![])
        };

        // Create bought_resource_vps
        let bought_resource_vps = TokenResource {
            token_name: swap.buy.name().clone(),
            resource: bought_resource,
        }
        .generate_output_token_vps(
            &mut rng,
            output_auth,
            input_resources,
            output_resources,
        );

        // Create the padding input vps
        let padding_input_vps = ResourceValidityPredicates::create_input_padding_resource_vps(
            &padding_input_resource,
            input_resources,
            output_resources,
        );

        // Create returned_resource_vps
        let returned_resource_vps = TokenResource {
            token_name: swap.sell.token_name().clone(),
            resource: returned_resource,
        }
        .generate_output_token_vps(
            &mut rng,
            output_auth,
            input_resources,
            output_resources,
        );

        (
            vec![intent_vps, padding_input_vps],
            vec![bought_resource_vps, returned_resource_vps],
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
    let (alice_ptx, swap, intent_resource) =
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
        bob_nk.get_npk(),
    );

    // Solver/Bob creates the partial transaction to consume the intent resource
    // The bob_ptx and solver_ptx can be merged to one ptx.
    let solver_ptx =
        consume_token_intent_ptx(&mut rng, swap, intent_resource, offer, alice_auth_pk);

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::new(vec![alice_ptx, bob_ptx, solver_ptx]);
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(&mut rng, shielded_tx_bundle, transparent_ptx_bundle).unwrap()
}

#[test]
fn test_partial_fulfillment_token_swap_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_transaction(&mut rng);
    tx.execute().unwrap();
}
