use halo2_proofs::arithmetic::Field;

use pasta_curves::pallas;
use rand::RngCore;

use taiga_halo2::{
    circuit::resource_logic_examples::{
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    compliance::ComplianceInfo,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    resource::{Resource, ResourceLogics},
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

    // padding the zero resources
    let padding_input_resource = Resource::random_padding_resource(&mut rng);
    let mut padding_output_resource = Resource::random_padding_resource(&mut rng);

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

        // Fetch a valid anchor for padding input resources
        let anchor = Anchor::from(pallas::Base::random(&mut rng));
        let compliance_2 = ComplianceInfo::new(
            padding_input_resource,
            merkle_path,
            Some(anchor),
            &mut padding_output_resource,
            &mut rng,
        );
        vec![compliance_1, compliance_2]
    };

    // Create resource logics
    let (input_resource_logics, output_resource_logics) = {
        let input_resources = [*input_resource.resource(), padding_input_resource];
        let output_resources = [*output_resource.resource(), padding_output_resource];
        // Create resource_logics for the input token
        let input_token_resource_logics = input_resource.generate_input_token_resource_logics(
            &mut rng,
            input_auth,
            input_auth_sk,
            input_resources,
            output_resources,
        );

        // Create resource logics for the output token
        let output_token_resource_logics = output_resource.generate_output_token_resource_logics(
            &mut rng,
            output_auth,
            input_resources,
            output_resources,
        );

        // Create resource logics for the padding input
        let padding_input_resource_logics =
            ResourceLogics::create_input_padding_resource_resource_logics(
                &padding_input_resource,
                input_resources,
                output_resources,
            );

        // Create resource logics for the padding output
        let padding_output_resource_logics =
            ResourceLogics::create_output_padding_resource_resource_logics(
                &padding_output_resource,
                input_resources,
                output_resources,
            );

        (
            vec![input_token_resource_logics, padding_input_resource_logics],
            vec![output_token_resource_logics, padding_output_resource_logics],
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
