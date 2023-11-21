use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateUpdateConfig {
    q_state_update: Selector,
    is_input_resource: Column<Advice>,
    pre_state_cell: Column<Advice>,
    cur_state_cell: Column<Advice>,
}

impl StateUpdateConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_input_resource: Column<Advice>,
        pre_state_cell: Column<Advice>,
        cur_state_cell: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_input_resource);
        meta.enable_equality(pre_state_cell);
        meta.enable_equality(cur_state_cell);

        let config = Self {
            q_state_update: meta.selector(),
            is_input_resource,
            pre_state_cell,
            cur_state_cell,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check state update", |meta| {
            let q_state_update = meta.query_selector(self.q_state_update);
            let is_input_resource = meta.query_advice(self.is_input_resource, Rotation::cur());
            let pre_state_cell = meta.query_advice(self.pre_state_cell, Rotation::cur());
            let cur_state_cell = meta.query_advice(self.cur_state_cell, Rotation::cur());

            let bool_check_is_input = bool_check(is_input_resource.clone());

            Constraints::with_selector(
                q_state_update,
                [
                    ("bool_check_is_input", bool_check_is_input),
                    (
                        "check state update",
                        is_input_resource * pre_state_cell.clone() * (pre_state_cell - cur_state_cell),
                    ),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        is_input_resource: &AssignedCell<pallas::Base, pallas::Base>,
        pre_state_cell: &AssignedCell<pallas::Base, pallas::Base>,
        cur_state_cell: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_state_update` selector
        self.q_state_update.enable(region, offset)?;

        is_input_resource.copy_advice(|| "is_input_resource", region, self.is_input_resource, offset)?;
        pre_state_cell.copy_advice(|| "pre_state_cell", region, self.pre_state_cell, offset)?;
        cur_state_cell.copy_advice(|| "cur_state_cell", region, self.cur_state_cell, offset)?;
        Ok(())
    }
}
