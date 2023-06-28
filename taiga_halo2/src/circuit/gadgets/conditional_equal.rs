/// Constrain flag * (lhs - rhs) = 0
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};

use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalEqualConfig {
    q_conditional_equal: Selector,
    advice: [Column<Advice>; 3],
}

impl ConditionalEqualConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice: [Column<Advice>; 3],
    ) -> Self {
        let config = Self {
            q_conditional_equal: meta.selector(),
            advice,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("conditional equal", |meta| {
            let q_conditional_equal = meta.query_selector(self.q_conditional_equal);

            let flag = meta.query_advice(self.advice[0], Rotation::cur());
            let lhs = meta.query_advice(self.advice[1], Rotation::cur());
            let rhs = meta.query_advice(self.advice[2], Rotation::cur());
            let poly = flag * (lhs - rhs);

            Constraints::with_selector(q_conditional_equal, [("flag * (lhs - rhs) = 0", poly)])
        });
    }

    pub fn assign_region(
        &self,
        flag: &AssignedCell<pallas::Base, pallas::Base>,
        lhs: &AssignedCell<pallas::Base, pallas::Base>,
        rhs: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_conditional_equal` selector
        self.q_conditional_equal.enable(region, offset)?;

        flag.copy_advice(|| "flag", region, self.advice[0], offset)?;
        lhs.copy_advice(|| "lhs", region, self.advice[1], offset)?;
        rhs.copy_advice(|| "rhs", region, self.advice[2], offset)?;

        Ok(())
    }
}
