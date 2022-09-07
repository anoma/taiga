use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, Error},
};

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
