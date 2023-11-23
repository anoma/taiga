use halo2_proofs::arithmetic::Field;

use pasta_curves::pallas;
use rand::RngCore;

use taiga_halo2::{
    action::ActionInfo,
    circuit::vp_examples::{
        signature_verification::COMPRESSED_TOKEN_AUTH_VK,
        token::{Token, TokenAuthorization},
    },
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{Anchor, MerklePath},
    resource::{Resource, ResourceValidityPredicates},
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
        output_token.create_random_output_token_resource(output_npk, &output_auth);

    // padding the zero resources
    let padding_input_resource = Resource::random_padding_resource(&mut rng);
    let mut padding_output_resource = Resource::random_padding_resource(&mut rng);

    // Generate proving info
    let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    // Create action pairs
    let actions = {
        let action_1 = ActionInfo::new(
            *input_resource.resource(),
            merkle_path.clone(),
            None,
            &mut output_resource.resource,
            &mut rng,
        );

        // Fetch a valid anchor for padding input resources
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
        let input_resources = [*input_resource.resource(), padding_input_resource];
        let output_resources = [*output_resource.resource(), padding_output_resource];
        // Create the input token vps
        let input_token_vps = input_resource.generate_input_token_vps(
            &mut rng,
            input_auth,
            input_auth_sk,
            input_resources,
            output_resources,
        );

        // Create the output token vps
        let output_token_vps = output_resource.generate_output_token_vps(
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

        // Create the padding output vps
        let padding_output_vps = ResourceValidityPredicates::create_output_padding_resource_vps(
            &padding_output_resource,
            input_resources,
            output_resources,
        );

        (
            vec![input_token_vps, padding_input_vps],
            vec![output_token_vps, padding_output_vps],
        )
    };

    // Create shielded partial tx
    ShieldedPartialTransaction::build(actions, input_vps, output_vps, vec![], &mut rng).unwrap()
}
