use ff::Field;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateUpdateConfig {
    q_state_update: Selector,
    is_spend_note: Column<Advice>,
    pre_state_cell: Column<Advice>,
    cur_state_cell: Column<Advice>,
}

impl StateUpdateConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_spend_note: Column<Advice>,
        pre_state_cell: Column<Advice>,
        cur_state_cell: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_spend_note);
        meta.enable_equality(pre_state_cell);
        meta.enable_equality(cur_state_cell);

        let config = Self {
            q_state_update: meta.selector(),
            is_spend_note,
            pre_state_cell,
            cur_state_cell,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check state update", |meta| {
            let q_state_update = meta.query_selector(self.q_state_update);
            let is_spend_note = meta.query_advice(self.is_spend_note, Rotation::cur());
            let pre_state_cell = meta.query_advice(self.pre_state_cell, Rotation::cur());
            let cur_state_cell = meta.query_advice(self.cur_state_cell, Rotation::cur());

            let bool_check_is_spend = bool_check(is_spend_note.clone());

            Constraints::with_selector(
                q_state_update,
                [
                    ("bool_check_is_spend", bool_check_is_spend),
                    (
                        "check state update",
                        is_spend_note * pre_state_cell.clone() * (pre_state_cell - cur_state_cell),
                    ),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        pre_state_cell: &AssignedCell<pallas::Base, pallas::Base>,
        cur_state_cell: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_state_update` selector
        self.q_state_update.enable(region, offset)?;

        is_spend_note.copy_advice(|| "is_spend_notex", region, self.is_spend_note, offset)?;
        pre_state_cell.copy_advice(|| "pre_state_cell", region, self.pre_state_cell, offset)?;
        cur_state_cell.copy_advice(|| "cur_state_cell", region, self.cur_state_cell, offset)?;
        Ok(())
    }
}
