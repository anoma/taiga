use crate::circuit::{
    gadgets::{
        assign_free_constant,
        conditional_equal::ConditionalEqualConfig,
        mul::{MulChip, MulInstructions},
        poseidon_hash::poseidon_hash_gadget,
        sub::{SubChip, SubInstructions},
    },
    resource_logic_circuit::ResourceStatus,
};
use halo2_gadgets::poseidon::Pow5Config as PoseidonConfig;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, Error},
};
use pasta_curves::pallas;

#[derive(Clone, Debug)]
pub struct PartialFulfillmentIntentLabel {
    pub token_resource_logic_vk: AssignedCell<pallas::Base, pallas::Base>,
    pub sold_token: AssignedCell<pallas::Base, pallas::Base>,
    pub sold_token_quantity: AssignedCell<pallas::Base, pallas::Base>,
    pub bought_token: AssignedCell<pallas::Base, pallas::Base>,
    pub bought_token_quantity: AssignedCell<pallas::Base, pallas::Base>,
    pub receiver_npk: AssignedCell<pallas::Base, pallas::Base>,
    pub receiver_value: AssignedCell<pallas::Base, pallas::Base>,
}

impl PartialFulfillmentIntentLabel {
    pub fn encode(
        &self,
        config: PoseidonConfig<pallas::Base, 3, 2>,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Encode the label of intent resource
        poseidon_hash_gadget(
            config.clone(),
            layouter.namespace(|| "label encoding"),
            [
                self.sold_token.clone(),
                self.sold_token_quantity.clone(),
                self.bought_token.clone(),
                self.bought_token_quantity.clone(),
                self.token_resource_logic_vk.clone(),
                self.receiver_npk.clone(),
                self.receiver_value.clone(),
            ],
        )
    }

    /// constraints on intent resource consumption
    pub fn intent_resource_consumption_check(
        &self,
        is_input_resource: &AssignedCell<pallas::Base, pallas::Base>,
        offer_resource: &ResourceStatus,
        config: &ConditionalEqualConfig,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "conditional equal: check bought token vk",
            |mut region| {
                config.assign_region(
                    is_input_resource,
                    &self.token_resource_logic_vk,
                    &offer_resource.resource.logic,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check bought token vk",
            |mut region| {
                config.assign_region(
                    is_input_resource,
                    &self.bought_token,
                    &offer_resource.resource.label,
                    0,
                    &mut region,
                )
            },
        )?;

        // check npk
        layouter.assign_region(
            || "conditional equal: check bought token npk",
            |mut region| {
                config.assign_region(
                    is_input_resource,
                    &self.receiver_npk,
                    &offer_resource.resource.npk,
                    0,
                    &mut region,
                )
            },
        )?;

        // check value
        layouter.assign_region(
            || "conditional equal: check bought token value",
            |mut region| {
                config.assign_region(
                    is_input_resource,
                    &self.receiver_value,
                    &offer_resource.resource.value,
                    0,
                    &mut region,
                )
            },
        )?;

        Ok(())
    }

    /// constraints on intent resource creation
    pub fn intent_resource_creation_check(
        &self,
        intent_resource: &ResourceStatus,
        sell_resource: &ResourceStatus,
        advices: &[Column<Advice>; 10],
        config: &ConditionalEqualConfig,
        sub_chip: &SubChip<pallas::Base>,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let is_output_resource = {
            let constant_one = assign_free_constant(
                layouter.namespace(|| "one"),
                advices[0],
                pallas::Base::one(),
            )?;
            // TODO: use a nor gate to replace the sub gate.
            SubInstructions::sub(
                sub_chip,
                layouter.namespace(|| "is_output"),
                &intent_resource.is_input,
                &constant_one,
            )?
        };

        layouter.assign_region(
            || "conditional equal: check sell token resource_logic_vk",
            |mut region| {
                config.assign_region(
                    &is_output_resource,
                    &self.token_resource_logic_vk,
                    &sell_resource.resource.logic,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check sell token label",
            |mut region| {
                config.assign_region(
                    &is_output_resource,
                    &self.sold_token,
                    &sell_resource.resource.label,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check sell token quantity",
            |mut region| {
                config.assign_region(
                    &is_output_resource,
                    &self.sold_token_quantity,
                    &sell_resource.resource.quantity,
                    0,
                    &mut region,
                )
            },
        )?;

        Ok(())
    }

    /// partial fulfillment check:
    /// validity of the returned resource
    /// partial fulfillment equation
    #[allow(clippy::too_many_arguments)]
    pub fn partial_fulfillment_check(
        &self,
        intent_resource: &ResourceStatus,
        offer_resource: &ResourceStatus,
        returned_resource: &ResourceStatus,
        config: &ConditionalEqualConfig,
        sub_chip: &SubChip<pallas::Base>,
        mul_chip: &MulChip<pallas::Base>,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let is_partial_fulfillment = {
            let is_partial_fulfillment = SubInstructions::sub(
                sub_chip,
                layouter
                    .namespace(|| "expected_bought_token_quantity - actual_bought_token_quantity"),
                &self.bought_token_quantity,
                &offer_resource.resource.quantity,
            )?;
            MulInstructions::mul(
                mul_chip,
                layouter.namespace(|| "is_input * is_partial_fulfillment"),
                &intent_resource.is_input,
                &is_partial_fulfillment,
            )?
        };

        // check: self_resource and returned_resource are on the same tree
        layouter.assign_region(
            || "conditional equal: check returned_resource root",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &intent_resource.resource_merkle_root,
                    &returned_resource.resource_merkle_root,
                    0,
                    &mut region,
                )
            },
        )?;

        // check the returned resource vk if it's partially fulfilled
        layouter.assign_region(
            || "conditional equal: check returned token vk",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.token_resource_logic_vk,
                    &returned_resource.resource.logic,
                    0,
                    &mut region,
                )
            },
        )?;

        // check the returned resource label if it's partially fulfilled
        layouter.assign_region(
            || "conditional equal: check returned token label",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.sold_token,
                    &returned_resource.resource.label,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check returned token npk",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.receiver_npk,
                    &returned_resource.resource.npk,
                    0,
                    &mut region,
                )
            },
        )?;

        layouter.assign_region(
            || "conditional equal: check returned token value",
            |mut region| {
                config.assign_region(
                    &is_partial_fulfillment,
                    &self.receiver_value,
                    &returned_resource.resource.value,
                    0,
                    &mut region,
                )
            },
        )?;

        // quantity check
        {
            let actual_sold_quantity = SubInstructions::sub(
                sub_chip,
                layouter.namespace(|| "expected_sold_quantity - returned_quantity"),
                &self.sold_token_quantity,
                &returned_resource.resource.quantity,
            )?;

            // check (expected_bought_quantity * actual_sold_quantity) == (expected_sold_quantity * actual_bought_quantity)
            // if it's partially fulfilled
            let expected_bought_mul_actual_sold_quantity = MulInstructions::mul(
                mul_chip,
                layouter.namespace(|| "expected_bought_quantity * actual_sold_quantity"),
                &self.bought_token_quantity,
                &actual_sold_quantity,
            )?;
            let expected_sold_mul_actual_bought_quantity = MulInstructions::mul(
                mul_chip,
                layouter.namespace(|| "expected_sold_quantity * actual_bought_quantity"),
                &self.sold_token_quantity,
                &offer_resource.resource.quantity,
            )?;

            layouter.assign_region(
                    || "conditional equal: expected_bought_quantity * actual_sold_quantity == expected_sold_quantity * actual_bought_quantity",
                    |mut region| {
                        config.assign_region(
                            &is_partial_fulfillment,
                            &expected_bought_mul_actual_sold_quantity,
                            &expected_sold_mul_actual_bought_quantity,
                            0,
                            &mut region,
                        )
                    },
                )?;
        }

        Ok(())
    }
}
