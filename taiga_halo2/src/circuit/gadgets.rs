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

pub mod add;
pub mod mul;
pub mod sub;
pub mod target_note_variable;
pub mod triple_mul;
pub mod value_check;

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
