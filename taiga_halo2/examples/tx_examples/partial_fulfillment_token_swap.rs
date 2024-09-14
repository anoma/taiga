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
    circuit::resource_logic_examples::{
        partial_fulfillment_intent::{PartialFulfillmentIntentResourceLogicCircuit, Swap},
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization, TokenResource},
    },
    compliance::ComplianceInfo,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    nullifier::NullifierKeyContainer,
    resource::{Resource, ResourceLogics},
    resource_tree::{ResourceExistenceWitness, ResourceMerkleTreeLeaves},
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

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create compliance pairs
    let compliances = {
        let compliance_1 = ComplianceInfo::new(
            *swap.sell.resource(),
            merkle_path.clone(),
            None,
            &mut intent_resource,
            &mut rng,
        );

        vec![compliance_1]
    };

    // Collect resource merkle leaves
    let input_resource_nf = swap.sell.resource().get_nf().unwrap().inner();
    let output_resource_cm = intent_resource.commitment().inner();
    let resource_merkle_tree =
        ResourceMerkleTreeLeaves::new(vec![input_resource_nf, output_resource_cm]);

    // Create input resource logics
    let input_merkle_path = resource_merkle_tree
        .generate_path(input_resource_nf)
        .unwrap();
    let input_resource_logics = swap.sell.generate_input_token_resource_logics(
        &mut rng,
        input_auth,
        input_auth_sk,
        input_merkle_path,
    );

    // Create intent resource logics
    let intent_resource_logics = {
        let sell_resource_witness =
            ResourceExistenceWitness::new(*swap.sell.resource(), input_merkle_path);

        let intent_resource_witness = {
            let merkle_path = resource_merkle_tree
                .generate_path(output_resource_cm)
                .unwrap();
            ResourceExistenceWitness::new(intent_resource, merkle_path)
        };

        let intent_circuit = PartialFulfillmentIntentResourceLogicCircuit {
            self_resource: intent_resource_witness,
            sell_resource: sell_resource_witness,
            offer_resource: ResourceExistenceWitness::default(), // a dummy resource
            returned_resource: ResourceExistenceWitness::default(), // a dummy resource
            swap: swap.clone(),
        };

        ResourceLogics::new(Box::new(intent_circuit), vec![])
    };

    // Create shielded partial tx
    let ptx = ShieldedPartialTransaction::build(
        compliances,
        vec![input_resource_logics],
        vec![intent_resource_logics],
        vec![],
        &mut rng,
    )
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
    let (mut offer_resource, mut returned_resource) = swap.fill(&mut rng, offer);
    let padding_input_resource = Resource::random_padding_resource(&mut rng);

    // output resources
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Fetch a valid anchor for dummy resources
    let anchor = Anchor::from(pallas::Base::random(&mut rng));

    // Create compliance pairs
    let compliances = {
        let compliance_1 = ComplianceInfo::new(
            intent_resource,
            merkle_path.clone(),
            Some(anchor),
            &mut offer_resource,
            &mut rng,
        );

        let compliance_2 = ComplianceInfo::new(
            padding_input_resource,
            merkle_path,
            Some(anchor),
            &mut returned_resource,
            &mut rng,
        );
        vec![compliance_1, compliance_2]
    };

    let intent_nf = intent_resource.get_nf().unwrap().inner();
    let offer_cm = offer_resource.commitment().inner();
    let padding_nf = padding_input_resource.get_nf().unwrap().inner();
    let returned_cm = returned_resource.commitment().inner();
    let resource_merkle_tree =
        ResourceMerkleTreeLeaves::new(vec![intent_nf, offer_cm, padding_nf, returned_cm]);

    // Create resource logics
    let (input_resource_logics, output_resource_logics) = {
        let intent_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(intent_nf).unwrap();
            ResourceExistenceWitness::new(intent_resource, merkle_path)
        };

        let offer_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(offer_cm).unwrap();
            ResourceExistenceWitness::new(offer_resource, merkle_path)
        };

        let padding_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(padding_nf).unwrap();
            ResourceExistenceWitness::new(padding_input_resource, merkle_path)
        };

        let returned_resource_witness = {
            let merkle_path = resource_merkle_tree.generate_path(returned_cm).unwrap();
            ResourceExistenceWitness::new(returned_resource, merkle_path)
        };

        // Create resource_logics for the intent
        let intent_resource_logics = {
            let intent_resource_logic = PartialFulfillmentIntentResourceLogicCircuit {
                self_resource: intent_resource_witness,
                sell_resource: padding_resource_witness, // a dummy one
                offer_resource: offer_resource_witness,
                returned_resource: returned_resource_witness,
                swap: swap.clone(),
            };

            ResourceLogics::new(Box::new(intent_resource_logic), vec![])
        };

        // Create resource_logics for the offer_resource
        let bought_resource_resource_logics = TokenResource {
            token_name: swap.buy.name().clone(),
            resource: offer_resource,
        }
        .generate_output_token_resource_logics(
            &mut rng,
            output_auth,
            offer_resource_witness.get_path(),
        );

        // Create resource_logics for the padding input
        let padding_input_resource_logics = ResourceLogics::create_padding_resource_resource_logics(
            padding_input_resource,
            padding_resource_witness.get_path(),
        );

        // Create resource_logics for the returned_resource
        let returned_resource_resource_logics = TokenResource {
            token_name: swap.sell.token_name().clone(),
            resource: returned_resource,
        }
        .generate_output_token_resource_logics(
            &mut rng,
            output_auth,
            returned_resource_witness.get_path(),
        );

        (
            vec![intent_resource_logics, padding_input_resource_logics],
            vec![
                bought_resource_resource_logics,
                returned_resource_resource_logics,
            ],
        )
    };

    // Create shielded partial tx
    ShieldedPartialTransaction::build(
        compliances,
        input_resource_logics,
        output_resource_logics,
        vec![],
        &mut rng,
    )
    .unwrap()
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
