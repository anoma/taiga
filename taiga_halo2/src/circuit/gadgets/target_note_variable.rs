use ff::Field;
use halo2_gadgets::utilities::ternary;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};

use pasta_curves::pallas;

use subtle::ConditionallySelectable;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetTargetNoteVariableConfig {
    q_get_target_variable: Selector,
    is_spend_note: Column<Advice>,
    spend_note_variable: Column<Advice>,
    output_note_variable: Column<Advice>,
    ret: Column<Advice>,
}

impl GetTargetNoteVariableConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_spend_note: Column<Advice>,
        spend_note_variable: Column<Advice>,
        output_note_variable: Column<Advice>,
        ret: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_spend_note);
        meta.enable_equality(spend_note_variable);
        meta.enable_equality(output_note_variable);
        meta.enable_equality(ret);

        let config = Self {
            q_get_target_variable: meta.selector(),
            is_spend_note,
            spend_note_variable,
            output_note_variable,
            ret,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("get target variable", |meta| {
            let q_get_target_variable = meta.query_selector(self.q_get_target_variable);
            let is_spend_note = meta.query_advice(self.is_spend_note, Rotation::cur());
            let spend_note_variable = meta.query_advice(self.spend_note_variable, Rotation::cur());
            let output_note_variable =
                meta.query_advice(self.output_note_variable, Rotation::cur());
            let ret = meta.query_advice(self.ret, Rotation::cur());

            let poly = ternary(
                is_spend_note.clone(),
                ret.clone() - spend_note_variable,
                ret - output_note_variable,
            );

            Constraints::with_selector(
                q_get_target_variable,
                [
                    ("bool_check is_spend_note", is_spend_note),
                    (
                        "if is_spend_note, then spend_note_variable, else output_note_variable",
                        poly,
                    ),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        is_spend_note: &AssignedCell<pallas::Base, pallas::Base>,
        spend_note_variable: &AssignedCell<pallas::Base, pallas::Base>,
        output_note_variable: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_get_target_variable` selector
        self.q_get_target_variable.enable(region, offset)?;

        // copy is_spend_note, y and z into the advice columns
        is_spend_note.copy_advice(|| "is_spend_note", region, self.is_spend_note, offset)?;
        spend_note_variable.copy_advice(
            || "spend_note_variable",
            region,
            self.spend_note_variable,
            offset,
        )?;
        output_note_variable.copy_advice(
            || "output_note_variable",
            region,
            self.output_note_variable,
            offset,
        )?;

        // create the corresponding affine point
        let ret = is_spend_note
            .value()
            .zip(spend_note_variable.value())
            .zip(output_note_variable.value())
            .map(
                |((&is_spend_note, &spend_note_variable), &output_note_variable)| {
                    pallas::Base::conditional_select(
                        &spend_note_variable,
                        &output_note_variable,
                        is_spend_note.is_zero(),
                    )
                },
            );
        region.assign_advice(|| "ret", self.ret, offset, || ret)
    }
}
