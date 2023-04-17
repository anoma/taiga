use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, Error, Instance},
    arithmetic
};

pub mod add;
pub mod mul;
pub mod sub;
pub mod target_note_variable;
pub mod triple_mul;

pub fn assign_free_advice<F: arithmetic::Field, V: Copy>(
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

pub fn assign_free_instance<F: arithmetic::Field>(
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

pub fn assign_free_constant<F: arithmetic::Field, V: Copy>(
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
