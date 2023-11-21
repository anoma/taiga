/// There are two properties in each condition of the extended or relation.
/// For example, we have condition one `A = (a1, a2)`, condition two `B = (b1, b2)` and target result `C = (c1, c2)`.
/// In the gadget, we need to satisfy `C == A` or `C == B`.
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};

use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedOrRelationConfig {
    q_extended_or_relation: Selector,
    advice: [Column<Advice>; 3],
}

impl ExtendedOrRelationConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice: [Column<Advice>; 3],
    ) -> Self {
        let config = Self {
            q_extended_or_relation: meta.selector(),
            advice,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("extended or relation", |meta| {
            let q_extended_or_relation = meta.query_selector(self.q_extended_or_relation);

            let is_input_resource_flag = meta.query_advice(self.advice[2], Rotation::cur());
            let a1 = meta.query_advice(self.advice[0], Rotation::prev());
            let a2 = meta.query_advice(self.advice[1], Rotation::prev());
            let b1 = meta.query_advice(self.advice[0], Rotation::cur());
            let b2 = meta.query_advice(self.advice[1], Rotation::cur());
            let c1 = meta.query_advice(self.advice[0], Rotation::next());
            let c2 = meta.query_advice(self.advice[1], Rotation::next());
            let poly1 = is_input_resource_flag.clone()
                * (c1.clone() - a1.clone())
                * (c1.clone() - b1.clone());
            let poly2 = is_input_resource_flag.clone()
                * (c2.clone() - a2.clone())
                * (c2.clone() - b2.clone());
            let poly3 = is_input_resource_flag.clone() * (c1.clone() - a1) * (c2.clone() - b2);
            let poly4 = is_input_resource_flag * (c1 - b1) * (c2 - a2);

            Constraints::with_selector(
                q_extended_or_relation,
                [
                    ("(c1-a1)(c1-b1) = 0", poly1),
                    ("(c2-a2)(c2-b2) = 0", poly2),
                    ("(c1-a1)(c2-b2) = 0", poly3),
                    ("(c1-b1)(c2-a2) = 0", poly4),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        is_input_resource_flag: &AssignedCell<pallas::Base, pallas::Base>,
        a: (
            &AssignedCell<pallas::Base, pallas::Base>,
            &AssignedCell<pallas::Base, pallas::Base>,
        ),
        b: (
            &AssignedCell<pallas::Base, pallas::Base>,
            &AssignedCell<pallas::Base, pallas::Base>,
        ),
        c: (
            &AssignedCell<pallas::Base, pallas::Base>,
            &AssignedCell<pallas::Base, pallas::Base>,
        ),
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_extended_or_relation` selector
        self.q_extended_or_relation.enable(region, offset + 1)?;

        is_input_resource_flag.copy_advice(
            || "is_input_resource_flag",
            region,
            self.advice[2],
            offset + 1,
        )?;
        a.0.copy_advice(|| "a1", region, self.advice[0], offset)?;
        a.1.copy_advice(|| "a2", region, self.advice[1], offset)?;
        b.0.copy_advice(|| "b1", region, self.advice[0], offset + 1)?;
        b.1.copy_advice(|| "b1", region, self.advice[1], offset + 1)?;
        c.0.copy_advice(|| "c1", region, self.advice[0], offset + 2)?;
        c.1.copy_advice(|| "c2", region, self.advice[1], offset + 2)?;

        Ok(())
    }
}
