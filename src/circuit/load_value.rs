use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::vesta;
use crate::note::Note;
use crate::nullifier::Nullifier;
use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;

use crate::circuit::circuit_parameters::CircuitParameters;

use halo2_gadgets::poseidon::{Pow5Config, Pow5Chip, primitives::P128Pow5T3};


pub fn load_private<CP: CircuitParameters>(
    advice_column: &Column<Advice>,
    mut layouter: impl Layouter<CP::CurveScalarField>,
    value: Value<CP::CurveScalarField>,
) -> Result<AssignedCell<CP::CurveScalarField, CP::CurveScalarField>, Error> {

    layouter.assign_region(
        || "load private",
        |mut region| {
            region
                .assign_advice(|| "private input", advice_column, 0, || value)
                
        },
    )
}

pub fn load_constant<CP: CircuitParameters>(
    advice_column: &Column<Advice>,
    mut layouter: impl Layouter<CP::CurveScalarField>,
    constant: CP::CurveScalarField,
) -> Result<AssignedCell<CP::CurveScalarField, CP::CurveScalarField>, Error> {

    layouter.assign_region(
        || "load constant",
        |mut region| {
            region
                .assign_advice_from_constant(|| "constant value", advice_column, 0, constant)
                
        },
    )
}