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
    state_product: Column<Advice>,
    value: Column<Advice>,
}

impl ValueCheckConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        state_product: Column<Advice>,
        value: Column<Advice>,
    ) -> Self {
        let config = Self {
            q_value_check: meta.selector(),
            state_product,
            value,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check state update", |meta| {
            let q_value_check = meta.query_selector(self.q_value_check);
            let state_product = meta.query_advice(self.state_product, Rotation::cur());
            let value = meta.query_advice(self.value, Rotation::cur());
            let state_product_inv = meta.query_advice(self.state_product, Rotation::next());
            let one = Expression::Constant(pallas::Base::one());
            let state_product_is_zero = one - state_product.clone() * state_product_inv;
            let poly = state_product_is_zero.clone() * state_product;

            let bool_check_value = bool_check(value.clone());

            Constraints::with_selector(
                q_value_check,
                [
                    ("bool_check_value", bool_check_value),
                    ("is_zero check", poly),
                    ("value check", (state_product_is_zero - value)),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        state_product: &AssignedCell<pallas::Base, pallas::Base>,
        value: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_value_check` selector
        self.q_value_check.enable(region, offset)?;

        state_product.copy_advice(|| "state_product", region, self.state_product, offset)?;
        value.copy_advice(|| "value", region, self.value, offset)?;
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
