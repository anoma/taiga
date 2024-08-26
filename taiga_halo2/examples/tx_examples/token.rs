use pasta_curves::pallas;
use rand::RngCore;

use taiga_halo2::{
    circuit::resource_logic_examples::{
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    compliance::ComplianceInfo,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    resource_tree::ResourceMerkleTreeLeaves,
    shielded_ptx::ShieldedPartialTransaction,
};

#[allow(clippy::too_many_arguments)]
pub fn create_token_swap_ptx<R: RngCore>(
    mut rng: R,
    input_token: Token,
    input_auth_sk: pallas::Scalar,
    input_nk: pallas::Base,
    output_token: Token,
    output_auth_pk: pallas::Point,
    output_npk: pallas::Base,
) -> ShieldedPartialTransaction {
    let input_auth = TokenAuthorization::from_sk_vk(&input_auth_sk, &COMPRESSED_TOKEN_AUTH_VK);

    // input resource
    let input_resource =
        input_token.create_random_input_token_resource(&mut rng, input_nk, &input_auth);

    // output resource
    let output_auth = TokenAuthorization::new(output_auth_pk, *COMPRESSED_TOKEN_AUTH_VK);
    let mut output_resource =
        output_token.create_random_output_token_resource(&mut rng, output_npk, &output_auth);

    // Generate proving info
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create compliance pairs
    let compliances = {
        let compliance_1 = ComplianceInfo::new(
            *input_resource.resource(),
            merkle_path.clone(),
            None,
            &mut output_resource.resource,
            &mut rng,
        );

        vec![compliance_1]
    };

    // Collect resource merkle leaves
    let input_resource_nf_1 = input_resource.get_nf().unwrap().inner();
    let output_resource_cm_1 = output_resource.commitment().inner();
    let resource_merkle_tree =
        ResourceMerkleTreeLeaves::new(vec![input_resource_nf_1, output_resource_cm_1]);

    // Create resource logics for the input resource

    let input_token_resource_logics = {
        let merkle_path = resource_merkle_tree
            .generate_path(input_resource_nf_1)
            .unwrap();
        input_resource.generate_input_token_resource_logics(
            &mut rng,
            input_auth,
            input_auth_sk,
            merkle_path,
        )
    };

    // Create resource logics for the output resource
    let output_token_resource_logics = {
        let merkle_path = resource_merkle_tree
            .generate_path(output_resource_cm_1)
            .unwrap();
        output_resource.generate_output_token_resource_logics(&mut rng, output_auth, merkle_path)
    };

    // Create shielded partial tx
    ShieldedPartialTransaction::build(
        compliances,
        vec![input_token_resource_logics],
        vec![output_token_resource_logics],
        vec![],
        &mut rng,
    )
    .unwrap()
}
