use crate::circuit::{
    gadgets::{
        conditional_equal::ConditionalEqualConfig,
        mul::{MulChip, MulInstructions},
        poseidon_hash::poseidon_hash_gadget,
        sub::{SubChip, SubInstructions},
    },
    vp_circuit::BasicValidityPredicateVariables,
};
use halo2_gadgets::poseidon::Pow5Config as PoseidonConfig;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::Error,
};
use pasta_curves::pallas;

#[derive(Clone, Debug)]
pub(super) struct PartialFulfillmentIntentDataStatic {
    pub(super) token_vp_vk: AssignedCell<pallas::Base, pallas::Base>,
    pub(super) sold_token: AssignedCell<pallas::Base, pallas::Base>,
    pub(super) sold_token_value: AssignedCell<pallas::Base, pallas::Base>,
    pub(super) bought_token: AssignedCell<pallas::Base, pallas::Base>,
    pub(super) bought_token_value: AssignedCell<pallas::Base, pallas::Base>,
    pub(super) receiver_nk_com: AssignedCell<pallas::Base, pallas::Base>,
    pub(super) receiver_app_data_dynamic: AssignedCell<pallas::Base, pallas::Base>,
}

impl PartialFulfillmentIntentDataStatic {
    pub(super) fn encode(
        &self,
        config: PoseidonConfig<pallas::Base, 3, 2>,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Encode the app_data_static of intent note
        poseidon_hash_gadget(
            config.clone(),
            layouter.namespace(|| "app_data_static encoding"),
            [
                self.sold_token.clone(),
                self.sold_token_value.clone(),
                self.bought_token.clone(),
                self.bought_token_value.clone(),
                self.token_vp_vk.clone(),
                self.receiver_nk_com.clone(),
                self.receiver_app_data_dynamic.clone(),
            ],
        )
    }

    /// Checks to be enforced if `is_input_note == 1`
    pub(super) fn is_input_note_checks(
        &self,
        is_input_note: &AssignedCell<pallas::Base, pallas::Base>,
        basic_variables: &BasicValidityPredicateVariables,
        config: &ConditionalEqualConfig,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "conditional equal: check bought token vk",
            |mut region| {
                config.assign_region(
                    is_input_note,
                    &self.token_vp_vk,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .app_vk,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check bought token vk",
            |mut region| {
                config.assign_region(
                    is_input_note,
                    &self.bought_token,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .app_data_static,
                    0,
                    &mut region,
                )
            },
        )?;

        // check nk_com
        layouter.assign_region(
            || "conditional equal: check bought token nk_com",
            |mut region| {
                config.assign_region(
                    is_input_note,
                    &self.receiver_nk_com,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .nk_com,
                    0,
                    &mut region,
                )
            },
        )?;

        // check app_data_dynamic
        layouter.assign_region(
            || "conditional equal: check bought token app_data_dynamic",
            |mut region| {
                config.assign_region(
                    is_input_note,
                    &self.receiver_app_data_dynamic,
                    &basic_variables.output_note_variables[0]
                        .note_variables
                        .app_data_dynamic,
                    0,
                    &mut region,
                )
            },
        )?;

        Ok(())
    }

    /// Checks to be enforced if `is_output_note == 1`
    pub(super) fn is_output_note_checks(
        &self,
        is_output_note: &AssignedCell<pallas::Base, pallas::Base>,
        basic_variables: &BasicValidityPredicateVariables,
        config: &ConditionalEqualConfig,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "conditional equal: check sold token vp_vk",
            |mut region| {
                config.assign_region(
                    is_output_note,
                    &self.token_vp_vk,
                    &basic_variables.input_note_variables[0]
                        .note_variables
                        .app_vk,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check sold token app_data_static",
            |mut region| {
                config.assign_region(
                    is_output_note,
                    &self.sold_token,
                    &basic_variables.input_note_variables[0]
                        .note_variables
                        .app_data_static,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check sold token value",
            |mut region| {
                config.assign_region(
                    is_output_note,
                    &self.sold_token_value,
                    &basic_variables.input_note_variables[0].note_variables.value,
                    0,
                    &mut region,
                )
            },
        )?;

        Ok(())
    }

    /// Checks to be enforced if `is_partial_fulfillment == 1`
    pub(super) fn is_partial_fulfillment_checks(
        &self,
        is_input_note: &AssignedCell<pallas::Base, pallas::Base>,
        basic_variables: &BasicValidityPredicateVariables,
        config: &ConditionalEqualConfig,
        sub_chip: &SubChip<pallas::Base>,
        mul_chip: &MulChip<pallas::Base>,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let is_partial_fulfillment = {
            let is_partial_fulfillment = SubInstructions::sub(
                sub_chip,
                layouter.namespace(|| "expected_bought_token_value - actual_bought_token_value"),
                &self.bought_token_value,
                &basic_variables.output_note_variables[0]
                    .note_variables
                    .value,
            )?;
            MulInstructions::mul(
                mul_chip,
                layouter.namespace(|| "is_input * is_partial_fulfillment"),
                is_input_note,
                &is_partial_fulfillment,
            )?
        };

        // check returned token vk if it's partially fulfilled
        layouter.assign_region(
            || "conditional equal: check returned token vk",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.token_vp_vk,
                    &basic_variables.output_note_variables[1]
                        .note_variables
                        .app_vk,
                    0,
                    &mut region,
                )
            },
        )?;

        // check return token app_data_static if it's partially fulfilled
        layouter.assign_region(
            || "conditional equal: check returned token app_data_static",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.sold_token,
                    &basic_variables.output_note_variables[1]
                        .note_variables
                        .app_data_static,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check returned token nk_com",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.receiver_nk_com,
                    &basic_variables.output_note_variables[1]
                        .note_variables
                        .nk_com,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check returned token app_data_dynamic",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.receiver_app_data_dynamic,
                    &basic_variables.output_note_variables[1]
                        .note_variables
                        .app_data_dynamic,
                    0,
                    &mut region,
                )
            },
        )?;

        // value check
        {
            let actual_sold_value = SubInstructions::sub(
                sub_chip,
                layouter.namespace(|| "expected_sold_value - returned_value"),
                &self.sold_token_value,
                &basic_variables.output_note_variables[1]
                    .note_variables
                    .value,
            )?;

            // check (expected_bought_value * actual_sold_value) == (expected_sold_value * actual_bought_value)
            // if it's partially fulfilled
            let expected_bought_mul_actual_sold_value = MulInstructions::mul(
                mul_chip,
                layouter.namespace(|| "expected_bought_value * actual_sold_value"),
                &self.bought_token_value,
                &actual_sold_value,
            )?;
            let expected_sold_mul_actual_bought_value = MulInstructions::mul(
                mul_chip,
                layouter.namespace(|| "expected_sold_value * actual_bought_value"),
                &self.sold_token_value,
                &basic_variables.output_note_variables[0]
                    .note_variables
                    .value,
            )?;

            layouter.assign_region(
                    || "conditional equal: expected_bought_value * actual_sold_value == expected_sold_value * actual_bought_value",
                    |mut region| {
                        config.assign_region(
                            &is_partial_fulfillment,
                            &expected_bought_mul_actual_sold_value,
                            &expected_sold_mul_actual_bought_value,
                            0,
                            &mut region,
                        )
                    },
                )?;
        }

        Ok(())
    }
}
