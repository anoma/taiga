use super::{PartialFulfillmentIntentDataStatic, COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK};
use crate::{
    circuit::{
        gadgets::assign_free_advice,
        vp_examples::token::{Token, TokenAuthorization, TokenNote, TOKEN_VK},
    },
    constant::NUM_NOTE,
    note::{Note, RandomSeed},
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
    pub sell: TokenNote,
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
        assert_eq!(buy.value() % sell.value(), 0);

        let sell = {
            let nk = pallas::Base::random(&mut rng);
            sell.create_random_input_token_note(&mut rng, nk, &auth)
        };

        Swap { sell, buy, auth }
    }

    /// Either:
    /// - completely fills the swap using a single `TokenNote`, or
    /// - partially fills the swap, producing a `TokenNote` and a
    ///   returned note.
    pub fn fill(
        &self,
        mut rng: impl RngCore,
        intent_note: Note,
        offer: Token,
    ) -> ([Note; NUM_NOTE], [Note; NUM_NOTE]) {
        assert_eq!(offer.name(), self.buy.name());

        let ratio = self.buy.value() / self.sell.value;
        assert_eq!(offer.value() % ratio, 0);

        let offer_note = offer.create_random_output_token_note(
            self.sell.note().nk_container.get_commitment(),
            &self.auth,
        );

        let input_padding_note = Note::random_padding_input_note(&mut rng);

        let returned_note = if offer.value() < self.buy.value() {
            let filled_value = offer.value() / ratio;
            let returned_value = self.sell.value - filled_value;
            let returned_token =
                Token::new(self.sell.token_name().inner().to_string(), returned_value);
            *returned_token
                .create_random_output_token_note(
                    self.sell.note().nk_container.get_commitment(),
                    &self.auth,
                )
                .note()
        } else {
            Note::random_padding_output_note(&mut rng, input_padding_note.get_nf().unwrap())
        };

        let input_notes = [intent_note, input_padding_note];
        let output_notes = [*offer_note.note(), returned_note];

        (input_notes, output_notes)
    }

    pub fn encode_app_data_static(&self) -> pallas::Base {
        poseidon_hash_n([
            self.sell.encode_name(),
            self.sell.encode_value(),
            self.buy.encode_name(),
            self.buy.encode_value(),
            // Assuming the sold_token and bought_token have the same TOKEN_VK
            TOKEN_VK.get_compressed(),
            self.sell.note().get_nk_commitment(),
            self.sell.note().app_data_dynamic,
        ])
    }

    pub fn create_intent_note<R: RngCore>(&self, mut rng: R) -> Note {
        let rseed = RandomSeed::random(&mut rng);

        Note::new_input_note(
            *COMPRESSED_PARTIAL_FULFILLMENT_INTENT_VK,
            self.encode_app_data_static(),
            pallas::Base::zero(),
            1u64,
            self.sell.note().nk_container.get_nk().unwrap(),
            self.sell.note().get_nf().unwrap(),
            false,
            rseed,
        )
    }

    /// Assign variables encoded in app_static_data
    pub fn assign_app_data_static(
        &self,
        column: Column<Advice>,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<PartialFulfillmentIntentDataStatic, Error> {
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

        let sold_token_value = assign_free_advice(
            layouter.namespace(|| "witness sold_token_value"),
            column,
            Value::known(self.sell.encode_value()),
        )?;

        let bought_token = assign_free_advice(
            layouter.namespace(|| "witness bought_token"),
            column,
            Value::known(self.buy.encode_name()),
        )?;

        let bought_token_value = assign_free_advice(
            layouter.namespace(|| "witness bought_token_value"),
            column,
            Value::known(self.buy.encode_value()),
        )?;

        let receiver_nk_com = assign_free_advice(
            layouter.namespace(|| "witness receiver nk_com"),
            column,
            Value::known(self.sell.note().get_nk_commitment()),
        )?;

        let receiver_app_data_dynamic = assign_free_advice(
            layouter.namespace(|| "witness receiver app_data_dynamic"),
            column,
            Value::known(self.sell.note().app_data_dynamic),
        )?;

        Ok(PartialFulfillmentIntentDataStatic {
            token_vp_vk,
            sold_token,
            sold_token_value,
            bought_token,
            bought_token_value,
            receiver_nk_com,
            receiver_app_data_dynamic,
        })
    }
}
