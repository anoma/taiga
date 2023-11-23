use super::{PartialFulfillmentIntentLabel, COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK};
use crate::{
    circuit::{
        gadgets::assign_free_advice,
        vp_examples::token::{Token, TokenAuthorization, TokenResource, TOKEN_VK},
    },
    constant::NUM_RESOURCE,
    resource::{RandomSeed, Resource},
    utils::poseidon_hash_n,
};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, Error},
};
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Clone, Debug, Default)]
pub struct Swap {
    pub sell: TokenResource,
    pub buy: Token,
    pub auth: TokenAuthorization,
}

impl Swap {
    pub fn random(
        mut rng: impl RngCore,
        sell: Token,
        buy: Token,
        auth: TokenAuthorization,
    ) -> Self {
        assert_eq!(buy.quantity() % sell.quantity(), 0);

        let sell = {
            let nk = pallas::Base::random(&mut rng);
            sell.create_random_input_token_resource(&mut rng, nk, &auth)
        };

        Swap { sell, buy, auth }
    }

    /// Either:
    /// - completely fills the swap using a single `TokenResource`, or
    /// - partially fills the swap, producing a `TokenResource` and a
    ///   returned resource.
    pub fn fill(
        &self,
        mut rng: impl RngCore,
        intent_resource: Resource,
        offer: Token,
    ) -> ([Resource; NUM_RESOURCE], [Resource; NUM_RESOURCE]) {
        assert_eq!(offer.name(), self.buy.name());

        let ratio = self.buy.quantity() / self.sell.quantity;
        assert_eq!(offer.quantity() % ratio, 0);

        let offer_resource = offer.create_random_output_token_resource(
            self.sell.resource().nk_container.get_commitment(),
            &self.auth,
        );

        let input_padding_resource = Resource::random_padding_resource(&mut rng);

        let returned_resource = if offer.quantity() < self.buy.quantity() {
            let filled_quantity = offer.quantity() / ratio;
            let returned_quantity = self.sell.quantity - filled_quantity;
            let returned_token = Token::new(
                self.sell.token_name().inner().to_string(),
                returned_quantity,
            );
            *returned_token
                .create_random_output_token_resource(
                    self.sell.resource().nk_container.get_commitment(),
                    &self.auth,
                )
                .resource()
        } else {
            Resource::random_padding_resource(&mut rng)
        };

        let input_resources = [intent_resource, input_padding_resource];
        let output_resources = [*offer_resource.resource(), returned_resource];

        (input_resources, output_resources)
    }

    pub fn encode_label(&self) -> pallas::Base {
        poseidon_hash_n([
            self.sell.encode_name(),
            self.sell.encode_quantity(),
            self.buy.encode_name(),
            self.buy.encode_quantity(),
            // Assuming the sold_token and bought_token have the same TOKEN_VK
            TOKEN_VK.get_compressed(),
            self.sell.resource().get_nk_commitment(),
            self.sell.resource().value,
        ])
    }

    pub fn create_intent_resource<R: RngCore>(&self, mut rng: R) -> Resource {
        let rseed = RandomSeed::random(&mut rng);

        Resource::new_input_resource(
            *COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK,
            self.encode_label(),
            pallas::Base::zero(),
            1u64,
            self.sell.resource().nk_container.get_nk().unwrap(),
            self.sell.resource().get_nf().unwrap(),
            false,
            rseed,
        )
    }

    /// Assign variables encoded in label
    pub fn assign_label(
        &self,
        column: Column<Advice>,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<PartialFulfillmentIntentLabel, Error> {
        let token_vp_vk = assign_free_advice(
            layouter.namespace(|| "witness token vp vk"),
            column,
            Value::known(TOKEN_VK.get_compressed()),
        )?;

        let sold_token = assign_free_advice(
            layouter.namespace(|| "witness sold_token"),
            column,
            Value::known(self.sell.encode_name()),
        )?;

        let sold_token_quantity = assign_free_advice(
            layouter.namespace(|| "witness sold_token_quantity"),
            column,
            Value::known(self.sell.encode_quantity()),
        )?;

        let bought_token = assign_free_advice(
            layouter.namespace(|| "witness bought_token"),
            column,
            Value::known(self.buy.encode_name()),
        )?;

        let bought_token_quantity = assign_free_advice(
            layouter.namespace(|| "witness bought_token_quantity"),
            column,
            Value::known(self.buy.encode_quantity()),
        )?;

        let receiver_nk_com = assign_free_advice(
            layouter.namespace(|| "witness receiver nk_com"),
            column,
            Value::known(self.sell.resource().get_nk_commitment()),
        )?;

        let receiver_value = assign_free_advice(
            layouter.namespace(|| "witness receiver value"),
            column,
            Value::known(self.sell.resource().value),
        )?;

        Ok(PartialFulfillmentIntentLabel {
            token_vp_vk,
            sold_token,
            sold_token_quantity,
            bought_token,
            bought_token_quantity,
            receiver_nk_com,
            receiver_value,
        })
    }
}
