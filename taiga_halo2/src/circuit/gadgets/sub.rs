use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
    arithmetic::Field
};

use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct SubChip<F: Field> {
    config: SubConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct SubConfig {
    advice: [Column<Advice>; 2],
    s_sub: Selector,
}

impl<F: Field> Chip<F> for SubChip<F> {
    type Config = SubConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> SubChip<F> {
    pub fn construct(
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
    ) -> <Self as Chip<F>>::Config {
        let s_sub = meta.selector();

        // Define our substraction gate!
        meta.create_gate("sub", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_sub = meta.query_selector(s_sub);

            vec![s_sub * (lhs - rhs - out)]
        });

        SubConfig { advice, s_sub }
    }
}

pub trait SubInstructions<F: Field>: Chip<F> {
    /// Returns `c = a - b`.
    fn sub(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

impl<F: Field> SubInstructions<F> for SubChip<F> {
    fn sub(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "sub",
            |mut region: Region<'_, F>| {
                // We only want to use a single substraction gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_sub.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can compute the substraction result, which is to be assigned
                // into the output position.
                let value = a.value().copied() - b.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region.assign_advice(|| "lhs - rhs", config.advice[0], 1, || value)
            },
        )
    }
}
