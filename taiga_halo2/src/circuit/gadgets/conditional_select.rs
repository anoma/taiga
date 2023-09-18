/// Constrain flag * (lhs - rhs) = 0
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalSelectConfig {
    q_conditional_select: Selector,
    advice: [Column<Advice>; 2],
}

impl ConditionalSelectConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice: [Column<Advice>; 2],
    ) -> Self {
        let config = Self {
            q_conditional_select: meta.selector(),
            advice,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("conditional select", |meta| {
            let q_conditional_select = meta.query_selector(self.q_conditional_select);

            let flag = meta.query_advice(self.advice[0], Rotation::cur());
            let ret = meta.query_advice(self.advice[0], Rotation::next());
            let lhs = meta.query_advice(self.advice[1], Rotation::cur());
            let rhs = meta.query_advice(self.advice[1], Rotation::next());
            let poly =
                flag.clone() * lhs + (Expression::Constant(pallas::Base::one()) - flag) * rhs - ret;

            Constraints::with_selector(
                q_conditional_select,
                [("flag * lhs + flag * rhs = ret", poly)],
            )
        });
    }

    pub fn assign_region(
        &self,
        flag: &AssignedCell<pallas::Base, pallas::Base>,
        lhs: &AssignedCell<pallas::Base, pallas::Base>,
        rhs: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_conditional_select` selector
        self.q_conditional_select.enable(region, offset)?;

        flag.copy_advice(|| "flag", region, self.advice[0], offset)?;
        let ret_value = flag
            .value()
            .zip(lhs.value())
            .zip(rhs.value())
            .map(|((flag, &lhs), &rhs)| flag * lhs + (pallas::Base::one() - flag) * rhs);

        lhs.copy_advice(|| "lhs", region, self.advice[1], offset)?;
        rhs.copy_advice(|| "rhs", region, self.advice[1], offset + 1)?;
        region.assign_advice(|| "ret", self.advice[0], offset + 1, || ret_value)
    }
}
