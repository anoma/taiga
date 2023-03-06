use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TripleMulConfig {
    q_triple_mul: Selector,
    advice: [Column<Advice>; 3],
}

impl TripleMulConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice: [Column<Advice>; 3],
    ) -> Self {
        let config = Self {
            q_triple_mul: meta.selector(),
            advice,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("triple mul", |meta| {
            let q_triple_mul = meta.query_selector(self.q_triple_mul);
            let first = meta.query_advice(self.advice[0], Rotation::cur());
            let second = meta.query_advice(self.advice[1], Rotation::cur());
            let third = meta.query_advice(self.advice[2], Rotation::cur());
            let out = meta.query_advice(self.advice[0], Rotation::next());

            vec![q_triple_mul * (first * second * third - out)]
        });
    }

    pub fn assign_region(
        &self,
        first: &AssignedCell<pallas::Base, pallas::Base>,
        second: &AssignedCell<pallas::Base, pallas::Base>,
        third: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_triple_mul` selector
        self.q_triple_mul.enable(region, offset)?;

        first.copy_advice(|| "first", region, self.advice[0], offset)?;
        second.copy_advice(|| "second", region, self.advice[1], offset)?;
        third.copy_advice(|| "third", region, self.advice[2], offset)?;
        let value = first.value() * second.value() * third.value();

        region.assign_advice(|| "out", self.advice[0], 1, || value)
    }
}
