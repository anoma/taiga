use ff::Field;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SudokuStateCheckConfig {
    q_state_check: Selector,
    is_spend_note: Column<Advice>,
    init_state: Column<Advice>,
    spend_note_app_data: Column<Advice>,
    spend_note_app_data_encoding: Column<Advice>,
    spend_note_vk: Column<Advice>,
    output_note_vk: Column<Advice>,
    spend_note_pre_state: Column<Advice>,
    output_note_cur_state: Column<Advice>,
}

impl SudokuStateCheckConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_spend_note: Column<Advice>,
        init_state: Column<Advice>,
        spend_note_app_data: Column<Advice>,
        spend_note_app_data_encoding: Column<Advice>,
        spend_note_vk: Column<Advice>,
        output_note_vk: Column<Advice>,
        spend_note_pre_state: Column<Advice>,
        output_note_cur_state: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_spend_note);
        meta.enable_equality(init_state);
        meta.enable_equality(spend_note_app_data);
        meta.enable_equality(spend_note_app_data_encoding);
        meta.enable_equality(spend_note_vk);
        meta.enable_equality(output_note_vk);
        meta.enable_equality(spend_note_pre_state);
        meta.enable_equality(output_note_cur_state);

        let config = Self {
            q_state_check: meta.selector(),
            is_spend_note,
            init_state,
            spend_note_app_data,
            spend_note_app_data_encoding,
            spend_note_vk,
            output_note_vk,
            spend_note_pre_state,
            output_note_cur_state,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check state", |meta| {
            let q_state_check = meta.query_selector(self.q_state_check);
            let is_spend_note = meta.query_advice(self.is_spend_note, Rotation::cur());
            let init_state = meta.query_advice(self.init_state, Rotation::cur());
            let spend_note_app_data = meta.query_advice(self.spend_note_app_data, Rotation::cur());
            let spend_note_app_data_encoding =
                meta.query_advice(self.spend_note_app_data_encoding, Rotation::cur());
            let spend_note_vk = meta.query_advice(self.spend_note_vk, Rotation::cur());
            let output_note_vk = meta.query_advice(self.output_note_vk, Rotation::cur());

            let spend_note_pre_state =
                meta.query_advice(self.spend_note_pre_state, Rotation::cur());
            let output_note_cur_state =
                meta.query_advice(self.output_note_cur_state, Rotation::cur());
            let pre_state_minus_cur_state = spend_note_pre_state - output_note_cur_state.clone();
            let pre_state_minus_cur_state_inv =
                meta.query_advice(self.spend_note_pre_state, Rotation::next());
            let one = Expression::Constant(pallas::Base::one());
            let pre_state_minus_cur_state_is_zero =
                one - pre_state_minus_cur_state.clone() * pre_state_minus_cur_state_inv;
            let poly = pre_state_minus_cur_state_is_zero.clone() * pre_state_minus_cur_state;

            let bool_check_is_spend = bool_check(is_spend_note.clone());

            Constraints::with_selector(
                q_state_check,
                [
                    ("bool_check_is_spend", bool_check_is_spend),
                    (
                        "check vk",
                        is_spend_note.clone() * (spend_note_vk.clone() - output_note_vk.clone()),
                    ),
                    (
                        "check spend_note_app_data_encoding",
                        is_spend_note.clone()
                            * (spend_note_app_data_encoding - spend_note_app_data),
                    ),
                    (
                        "check puzzle init",
                        (init_state - output_note_cur_state) * (output_note_vk - spend_note_vk),
                    ),
                    ("is_zero check", poly),
                    (
                        "pre_state != cur_state",
                        is_spend_note * pre_state_minus_cur_state_is_zero,
                    ),
                ],
            )
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_region(
        &self,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        init_state: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_app_data: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_app_data_encoding: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_vk: &AssignedCell<pallas::Base, pallas::Base>,
        output_note_vk: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_pre_state: &AssignedCell<pallas::Base, pallas::Base>,
        output_note_cur_state: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_state_check` selector
        self.q_state_check.enable(region, offset)?;

        is_spend_note.copy_advice(|| "is_spend_notex", region, self.is_spend_note, offset)?;
        init_state.copy_advice(|| "init_state", region, self.init_state, offset)?;
        spend_note_app_data.copy_advice(
            || "spend_note_app_data",
            region,
            self.spend_note_app_data,
            offset,
        )?;
        spend_note_app_data_encoding.copy_advice(
            || "spend_note_app_data_encoding",
            region,
            self.spend_note_app_data_encoding,
            offset,
        )?;
        spend_note_vk.copy_advice(|| "spend_note_vk", region, self.spend_note_vk, offset)?;
        output_note_vk.copy_advice(|| "output_note_vk", region, self.output_note_vk, offset)?;
        spend_note_pre_state.copy_advice(
            || "spend_note_pre_state",
            region,
            self.spend_note_pre_state,
            offset,
        )?;
        output_note_cur_state.copy_advice(
            || "output_note_cur_state",
            region,
            self.output_note_cur_state,
            offset,
        )?;
        let pre_state_minus_cur_state_inv = spend_note_pre_state
            .value()
            .zip(output_note_cur_state.value())
            .map(|(pre, cur)| (pre - cur).invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(
            || "pre_state_minus_cur_state_inv",
            self.spend_note_pre_state,
            offset + 1,
            || pre_state_minus_cur_state_inv,
        )?;

        Ok(())
    }
}
