use ff::Field;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueCheckConfig {
    q_value_check: Selector,
    is_spend_note: Column<Advice>,
    state_product: Column<Advice>,
    value: Column<Advice>,
}

impl ValueCheckConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_spend_note: Column<Advice>,
        state_product: Column<Advice>,
        value: Column<Advice>,
    ) -> Self {
        let config = Self {
            q_value_check: meta.selector(),
            is_spend_note,
            state_product,
            value,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check state update", |meta| {
            let q_value_check = meta.query_selector(self.q_value_check);
            let is_spend_note = meta.query_advice(self.is_spend_note, Rotation::cur());
            let state_product = meta.query_advice(self.state_product, Rotation::cur());
            let spend_value = meta.query_advice(self.value, Rotation::cur());
            let output_value = meta.query_advice(self.value, Rotation::next());
            let state_product_inv = meta.query_advice(self.state_product, Rotation::next());
            let one = Expression::Constant(pallas::Base::one());
            let state_product_is_zero = one - state_product.clone() * state_product_inv;
            let poly = state_product_is_zero.clone() * state_product;

            let bool_check_value = bool_check(output_value.clone());
            let one = Expression::Constant(pallas::Base::one());

            Constraints::with_selector(
                q_value_check,
                [
                    ("bool_check_value", bool_check_value),
                    ("is_zero check", poly),
                    ("output value check", (state_product_is_zero - output_value)),
                    ("spend value check", is_spend_note * (spend_value - one)),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        state_product: &AssignedCell<pallas::Base, pallas::Base>,
        spend_value: &AssignedCell<pallas::Base, pallas::Base>,
        output_value: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_value_check` selector
        self.q_value_check.enable(region, offset)?;
        is_spend_note.copy_advice(|| "is_spend_notex", region, self.is_spend_note, offset)?;
        state_product.copy_advice(|| "state_product", region, self.state_product, offset)?;
        spend_value.copy_advice(|| "spend value", region, self.value, offset)?;
        output_value.copy_advice(|| "output value", region, self.value, offset + 1)?;
        let state_product_inv = state_product
            .value()
            .map(|state_product| state_product.invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(
            || "state_product_inv",
            self.state_product,
            offset + 1,
            || state_product_inv,
        )?;
        Ok(())
    }
}
