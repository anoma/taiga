/// Token swap example with intent resource
/// Alice has 5 "BTC" and wants 1 "DOLPHIN" or 2 "Monkeys". Then Alice creates an intent for it.
/// Bob has 1 "DOLPHIN" and wants 5 "BTC".
/// The Solver/Bob matches Alice's intent and creates the final tx.
///
use crate::token::create_token_swap_ptx;
use group::Group;
use halo2_proofs::arithmetic::Field;
use pasta_curves::{group::Curve, pallas};
use rand::{CryptoRng, RngCore};
use taiga_halo2::{
    circuit::resource_logic_examples::{
        or_relation_intent::{create_intent_resource, OrRelationIntentResourceLogicCircuit},
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    compliance::ComplianceInfo,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    nullifier::NullifierKeyContainer,
    resource::ResourceLogics,
    resource_tree::{ResourceExistenceWitness, ResourceMerkleTreeLeaves},
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};

pub fn create_token_intent_ptx<R: RngCore>(
    mut rng: R,
    token_1: Token,
    token_2: Token,
    input_token: Token,
    input_auth_sk: pallas::Scalar,
    input_nk: pallas::Base,
) -> (
    ShieldedPartialTransaction,
    pallas::Base,
    pallas::Base,
    pallas::Base,
) {
    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);

    // input resource
    let input_resource =
        input_token.create_random_input_token_resource(&mut rng, input_nk, &input_auth);

    // output intent resource
    let input_resource_npk = input_resource.get_npk();
    let mut intent_resource = create_intent_resource(
        &mut rng,
        &token_1,
        &token_2,
        input_resource_npk,
        input_resource.value,
        input_nk,
    );

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create compliance pairs
    let compliances = {
        let compliance_1 = ComplianceInfo::new(
            *input_resource.resource(),
            merkle_path.clone(),
            None,
            &mut intent_resource,
            &mut rng,
        );

        vec![compliance_1]
    };

    // Collect resource merkle leaves
    let input_resource_nf = input_resource.get_nf().unwrap().inner();
    let output_resource_cm = intent_resource.commitment().inner();
    let resource_merkle_tree =
        ResourceMerkleTreeLeaves::new(vec![input_resource_nf, output_resource_cm]);

    // Create resource logics for the input resource
    let input_resource_resource_logics = {
        let merkle_path = resource_merkle_tree
            .generate_path(input_resource_nf)
            .unwrap();
        input_resource.generate_input_token_resource_logics(
            &mut rng,
            input_auth,
            input_auth_sk,
            merkle_path,
        )
    };

    // Create resource logics for the intent(output) resource
    let output_resource_resource_logics = {
        let merkle_path = resource_merkle_tree
            .generate_path(output_resource_cm)
            .unwrap();
        let intent_resource_witness = ResourceExistenceWitness::new(intent_resource, merkle_path);
        let circuit = OrRelationIntentResourceLogicCircuit {
            self_resource: intent_resource_witness,
            // the desired resource won't be checked.
            desired_resource: intent_resource_witness,
            token_1,
            token_2,
            receiver_npk: input_resource_npk,
            receiver_value: input_resource.value,
        };
        ResourceLogics::new(Box::new(circuit), vec![])
    };

    // Create shielded partial tx
    let ptx = ShieldedPartialTransaction::build(
        compliances,
        vec![input_resource_resource_logics],
        vec![output_resource_resource_logics],
        vec![],
        &mut rng,
    )
    .unwrap();

    (ptx, input_nk, input_resource_npk, input_resource.value)
}

#[allow(clippy::too_many_arguments)]
pub fn consume_token_intent_ptx<R: RngCore>(
    mut rng: R,
    token_1: Token,
    token_2: Token,
    input_nk: pallas::Base,
    receiver_npk: pallas::Base,
    receiver_value: pallas::Base,
    output_token: Token,
    output_auth_pk: pallas::Point,
) -> ShieldedPartialTransaction {
    // input intent resource
    let intent_resource = create_intent_resource(
        &mut rng,
        &token_1,
        &token_2,
        receiver_npk,
        receiver_value,
        input_nk,
    );

    // output resource
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
    let output_npk = NullifierKeyContainer::from_key(input_nk).get_npk();
    let mut output_resource =
        output_token.create_random_output_token_resource(&mut rng, output_npk, &output_auth);

    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Fetch a valid anchor for dummy resources
    let anchor = Anchor::from(pallas::Base::random(&mut rng));

    // Create compliance proof
    let compliance = ComplianceInfo::new(
        intent_resource,
        merkle_path.clone(),
        Some(anchor),
        &mut output_resource.resource,
        &mut rng,
    );

    let input_resource_nf = intent_resource.get_nf().unwrap().inner();
    let output_resource_cm = output_resource.commitment().inner();
    let resource_merkle_tree =
        ResourceMerkleTreeLeaves::new(vec![input_resource_nf, output_resource_cm]);

    let output_merkle_path = resource_merkle_tree
        .generate_path(output_resource_cm)
        .unwrap();

    // Create resource logics for the intent(input) resource
    let intent_resource_logics = {
        let merkle_path = resource_merkle_tree
            .generate_path(input_resource_nf)
            .unwrap();
        let intent_resource_logic = OrRelationIntentResourceLogicCircuit {
            self_resource: ResourceExistenceWitness::new(intent_resource, merkle_path),
            desired_resource: ResourceExistenceWitness::new(
                output_resource.resource,
                output_merkle_path,
            ),
            token_1,
            token_2,
            receiver_npk,
            receiver_value,
        };

        ResourceLogics::new(Box::new(intent_resource_logic), vec![])
    };

    let output_resource_logics = output_resource.generate_output_token_resource_logics(
        &mut rng,
        output_auth,
        output_merkle_path,
    );

    // Create shielded partial tx
    ShieldedPartialTransaction::build(
        vec![compliance],
        vec![intent_resource_logics],
        vec![output_resource_logics],
        vec![],
        &mut rng,
    )
    .unwrap()
}

pub fn create_token_swap_intent_transaction<R: RngCore + CryptoRng>(mut rng: R) -> Transaction {
    let generator = pallas::Point::generator().to_affine();

    // Alice creates the partial transaction with 5 BTC input and intent output
    let alice_auth_sk = pallas::Scalar::random(&mut rng);
    let alice_auth_pk = generator * alice_auth_sk;
    let alice_nk = pallas::Base::random(&mut rng);
    let token_1 = Token::new("dolphin".to_string(), 1u64);
    let token_2 = Token::new("monkey".to_string(), 2u64);
    let btc_token = Token::new("btc".to_string(), 5u64);
    let (alice_ptx, intent_nk, receiver_npk, receiver_value) = create_token_intent_ptx(
        &mut rng,
        token_1.clone(),
        token_2.clone(),
        btc_token.clone(),
        alice_auth_sk,
        alice_nk,
    );

    // Bob creates the partial transaction with 1 DOLPHIN input and 5 BTC output
    let bob_auth_sk = pallas::Scalar::random(&mut rng);
    let bob_auth_pk = generator * bob_auth_sk;
    let bob_nk = NullifierKeyContainer::random_key(&mut rng);

    let bob_ptx = create_token_swap_ptx(
        &mut rng,
        token_1.clone(),
        bob_auth_sk,
        bob_nk.get_nk().unwrap(),
        btc_token,
        bob_auth_pk,
        bob_nk.get_npk(),
    );

    // Solver/Bob creates the partial transaction to consume the intent resource
    // The bob_ptx and solver_ptx can be merged to one ptx.
    let solver_ptx = consume_token_intent_ptx(
        &mut rng,
        token_1.clone(),
        token_2,
        intent_nk,
        receiver_npk,
        receiver_value,
        token_1,
        alice_auth_pk,
    );

    // Solver creates the final transaction
    let shielded_tx_bundle = ShieldedPartialTxBundle::new(vec![alice_ptx, bob_ptx, solver_ptx]);
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(&mut rng, shielded_tx_bundle, transparent_ptx_bundle).unwrap()
}

#[test]
fn test_token_swap_intent_tx() {
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let tx = create_token_swap_intent_transaction(&mut rng);
    tx.execute().unwrap();
}
