use ff::Field;
use halo2_gadgets::utilities::ternary;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::arithmetic::FieldExt;
use pasta_curves::pallas;
use std::marker::PhantomData;
use subtle::ConditionallySelectable;

pub fn assign_free_advice<F: Field, V: Copy>(
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: Value<V>,
) -> Result<AssignedCell<V, F>, Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    layouter.assign_region(
        || "load private",
        |mut region| region.assign_advice(|| "load private", column, 0, || value),
    )
}

pub fn assign_free_instance<F: Field>(
    mut layouter: impl Layouter<F>,
    instance: Column<Instance>,
    row: usize,
    advice: Column<Advice>,
) -> Result<AssignedCell<F, F>, Error> {
    layouter.assign_region(
        || "load instance",
        |mut region| {
            region.assign_advice_from_instance(|| "load instance", instance, row, advice, 0)
        },
    )
}

pub fn assign_free_constant<F: Field, V: Copy>(
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: V,
) -> Result<AssignedCell<V, F>, Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    layouter.assign_region(
        || "load constant",
        |mut region| region.assign_advice_from_constant(|| "load constant", column, 0, value),
    )
}

// AddChip copy from halo2 example two-chip
#[derive(Clone, Debug)]
pub struct AddChip<F: FieldExt> {
    config: AddConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct AddConfig {
    advice: [Column<Advice>; 2],
    s_add: Selector,
}

impl<F: FieldExt> Chip<F> for AddChip<F> {
    type Config = AddConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> AddChip<F> {
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
        let s_add = meta.selector();

        // Define our addition gate!
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (lhs + rhs - out)]
        });

        AddConfig { advice, s_add }
    }
}

pub trait AddInstructions<F: FieldExt>: Chip<F> {
    /// Returns `c = a + b`.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

impl<F: FieldExt> AddInstructions<F> for AddChip<F> {
    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region: Region<'_, F>| {
                // We only want to use a single addition gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_add.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can compute the addition result, which is to be assigned
                // into the output position.
                let value = a.value().copied() + b.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region.assign_advice(|| "lhs + rhs", config.advice[0], 1, || value)
            },
        )
    }
}

/// ----------------------------

#[derive(Clone, Debug)]
pub struct SubChip<F: FieldExt> {
    config: SubConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct SubConfig {
    advice: [Column<Advice>; 2],
    s_sub: Selector,
}

impl<F: FieldExt> Chip<F> for SubChip<F> {
    type Config = SubConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> SubChip<F> {
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

pub trait SubInstructions<F: FieldExt>: Chip<F> {
    /// Returns `c = a - b`.
    fn sub(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

impl<F: FieldExt> SubInstructions<F> for SubChip<F> {
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

/// ----------------------------

/// An instruction set for multiplying two circuit words (field elements).
pub trait MulInstructions<F: FieldExt>: Chip<F> {
    /// Constraints `a * b` and returns the multiplication.
    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

#[derive(Clone, Debug)]
pub struct MulConfig {
    advice: [Column<Advice>; 2],
    s_mul: Selector,
}

/// A chip implementing a single multiplication constraint `c = a * b` on a single row.
pub struct MulChip<F: FieldExt> {
    config: MulConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for MulChip<F> {
    type Config = MulConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> MulChip<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, advice: [Column<Advice>; 2]) -> MulConfig {
        let s_mul = meta.selector();
        meta.create_gate("Field element multiplication: c = a * b", |meta| {
            let s_mul = meta.query_selector(s_mul);
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());

            vec![s_mul * (lhs * rhs - out)]
        });

        MulConfig { advice, s_mul }
    }

    pub fn construct(config: MulConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt> MulInstructions<F> for MulChip<F> {
    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                // We only want to use a single addition gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                self.config.s_mul.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.copy_advice(|| "lhs", &mut region, self.config.advice[0], 0)?;
                b.copy_advice(|| "rhs", &mut region, self.config.advice[1], 0)?;

                // Now we can compute the addition result, which is to be assigned
                // into the output position.
                let value = a.value().copied() * b.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region.assign_advice(|| "lhs * rhs", self.config.advice[0], 1, || value)
            },
        )
    }
}

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
