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
    is_input_resource: Column<Advice>,
    init_state: Column<Advice>,
    input_resource_app_data_static: Column<Advice>,
    input_resource_app_data_static_encoding: Column<Advice>,
    input_resource_vk: Column<Advice>,
    output_resource_vk: Column<Advice>,
    input_resource_pre_state: Column<Advice>,
    output_resource_cur_state: Column<Advice>,
}

impl SudokuStateCheckConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_input_resource: Column<Advice>,
        init_state: Column<Advice>,
        input_resource_app_data_static: Column<Advice>,
        input_resource_app_data_static_encoding: Column<Advice>,
        input_resource_vk: Column<Advice>,
        output_resource_vk: Column<Advice>,
        input_resource_pre_state: Column<Advice>,
        output_resource_cur_state: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_input_resource);
        meta.enable_equality(init_state);
        meta.enable_equality(input_resource_app_data_static);
        meta.enable_equality(input_resource_app_data_static_encoding);
        meta.enable_equality(input_resource_vk);
        meta.enable_equality(output_resource_vk);
        meta.enable_equality(input_resource_pre_state);
        meta.enable_equality(output_resource_cur_state);

        let config = Self {
            q_state_check: meta.selector(),
            is_input_resource,
            init_state,
            input_resource_app_data_static,
            input_resource_app_data_static_encoding,
            input_resource_vk,
            output_resource_vk,
            input_resource_pre_state,
            output_resource_cur_state,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check state", |meta| {
            let q_state_check = meta.query_selector(self.q_state_check);
            let is_input_resource = meta.query_advice(self.is_input_resource, Rotation::cur());
            let init_state = meta.query_advice(self.init_state, Rotation::cur());
            let input_resource_app_data_static =
                meta.query_advice(self.input_resource_app_data_static, Rotation::cur());
            let input_resource_app_data_static_encoding =
                meta.query_advice(self.input_resource_app_data_static_encoding, Rotation::cur());
            let input_resource_vk = meta.query_advice(self.input_resource_vk, Rotation::cur());
            let output_resource_vk = meta.query_advice(self.output_resource_vk, Rotation::cur());

            let input_resource_pre_state =
                meta.query_advice(self.input_resource_pre_state, Rotation::cur());
            let output_resource_cur_state =
                meta.query_advice(self.output_resource_cur_state, Rotation::cur());
            let pre_state_minus_cur_state = input_resource_pre_state - output_resource_cur_state.clone();
            let pre_state_minus_cur_state_inv =
                meta.query_advice(self.input_resource_pre_state, Rotation::next());
            let one = Expression::Constant(pallas::Base::one());
            let pre_state_minus_cur_state_is_zero =
                one - pre_state_minus_cur_state.clone() * pre_state_minus_cur_state_inv;
            let poly = pre_state_minus_cur_state_is_zero.clone() * pre_state_minus_cur_state;

            let bool_check_is_input = bool_check(is_input_resource.clone());

            Constraints::with_selector(
                q_state_check,
                [
                    ("bool_check_is_input", bool_check_is_input),
                    (
                        "check vk",
                        is_input_resource.clone() * (input_resource_vk.clone() - output_resource_vk.clone()),
                    ),
                    (
                        "check input_resource_app_data_static_encoding",
                        is_input_resource.clone()
                            * (input_resource_app_data_static_encoding - input_resource_app_data_static),
                    ),
                    (
                        "check puzzle init",
                        (init_state - output_resource_cur_state) * (output_resource_vk - input_resource_vk),
                    ),
                    ("is_zero check", poly),
                    (
                        "pre_state != cur_state",
                        is_input_resource * pre_state_minus_cur_state_is_zero,
                    ),
                ],
            )
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_region(
        &self,
        is_input_resource: &AssignedCell<pallas::Base, pallas::Base>,
        init_state: &AssignedCell<pallas::Base, pallas::Base>,
        input_resource_app_data_static: &AssignedCell<pallas::Base, pallas::Base>,
        input_resource_app_data_static_encoding: &AssignedCell<pallas::Base, pallas::Base>,
        input_resource_vk: &AssignedCell<pallas::Base, pallas::Base>,
        output_resource_vk: &AssignedCell<pallas::Base, pallas::Base>,
        input_resource_pre_state: &AssignedCell<pallas::Base, pallas::Base>,
        output_resource_cur_state: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_state_check` selector
        self.q_state_check.enable(region, offset)?;

        is_input_resource.copy_advice(|| "is_input_resourcex", region, self.is_input_resource, offset)?;
        init_state.copy_advice(|| "init_state", region, self.init_state, offset)?;
        input_resource_app_data_static.copy_advice(
            || "input_resource_app_data_static",
            region,
            self.input_resource_app_data_static,
            offset,
        )?;
        input_resource_app_data_static_encoding.copy_advice(
            || "input_resource_app_data_static_encoding",
            region,
            self.input_resource_app_data_static_encoding,
            offset,
        )?;
        input_resource_vk.copy_advice(|| "input_resource_vk", region, self.input_resource_vk, offset)?;
        output_resource_vk.copy_advice(|| "output_resource_vk", region, self.output_resource_vk, offset)?;
        input_resource_pre_state.copy_advice(
            || "input_resource_pre_state",
            region,
            self.input_resource_pre_state,
            offset,
        )?;
        output_resource_cur_state.copy_advice(
            || "output_resource_cur_state",
            region,
            self.output_resource_cur_state,
            offset,
        )?;
        let pre_state_minus_cur_state_inv = input_resource_pre_state
            .value()
            .zip(output_resource_cur_state.value())
            .map(|(pre, cur)| (pre - cur).invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(
            || "pre_state_minus_cur_state_inv",
            self.input_resource_pre_state,
            offset + 1,
            || pre_state_minus_cur_state_inv,
        )?;

        Ok(())
    }
}
