use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};
use pasta_curves::{pallas, Fp};

/*
This file is for educational purpose.
We want to create a circuit corresponding to a square root computation.
Given x, and y=sqrt(x), it checks that y is a square root of x.
*/

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqrtConfig {
    is_square: Selector,
    x: Column<Advice>,
    y: Column<Advice>,
}

impl SqrtConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        x: Column<Advice>,
        y: Column<Advice>,
    ) -> Self {
        meta.enable_equality(x);
        meta.enable_equality(y);

        let config = Self {
            is_square: meta.selector(),
            x,
            y,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("y² == x", |meta| {
            // 1. We get x and y from the column `self.x` and `self.y`
            // 2. We create a constrain corresponding to y^2 - x == 0
            let is_square = meta.query_selector(self.is_square);
            let x = meta.query_advice(self.x, Rotation::cur());
            let y = meta.query_advice(self.y, Rotation::cur());

            let x_is_y_square = y.clone() * y.clone() - x.clone();

            Constraints::with_selector(is_square, [("y is the sqrt of x", x_is_y_square)])
        });
    }

    pub fn assign_region(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        // this function set the value of x and y needed for the sqrt circuit
        self.is_square.enable(region, offset).unwrap();
        x.copy_advice(|| "x", region, self.x, offset)?;
        let y = x.value().map(|x| x.sqrt().unwrap_or(pallas::Base::zero()));
        Ok(region.assign_advice(|| "sqrt(x)", self.y, offset, || y)?)
    }
}

#[test]
fn test_sqrt_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };

    #[derive(Default)]
    struct MySqrtCircuit {
        x: Fp,
    }

    impl Circuit<pallas::Base> for MySqrtCircuit {
        type Config = ([Column<Advice>; 10], SqrtConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];

            let is_square_config = SqrtConfig::configure(meta, advices[0], advices[1]);

            // let table_idx = meta.lookup_table_column();
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            (advices, is_square_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, _) = config;

            // create a cell for x
            let x_cell =
                assign_free_advice(layouter.namespace(|| "x"), advices[0], Value::known(self.x))?;

            // create a cell for sqrt(x) in-circuit using SqrtConfig.assign_region()
            layouter.assign_region(
                || "sqrt(x) in-circuit",
                |mut region| config.1.assign_region(&x_cell, 0, &mut region),
            )?;

            Ok(())
        }
    }

    let circuit1 = MySqrtCircuit { x: Fp::from(4) };
    let circuit2 = MySqrtCircuit {
        x: Fp::from(5), // 5 is not a square in Pallas::BaseField.
    };

    let prover1 = MockProver::run(3, &circuit1, vec![]).unwrap();
    let prover2 = MockProver::run(3, &circuit2, vec![]).unwrap();

    assert_eq!(prover1.verify(), Ok(()));
    assert_ne!(prover2.verify(), Ok(()));
}
