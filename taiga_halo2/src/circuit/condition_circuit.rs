use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::{pallas, Fp};

/*
This file is for educational purpose.
We want to create a conditional gate in-circuit.
We take the example of the circuit of:
if x == 0 :
    return 12
else :
    return 34
*/

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalConfig {
    cond: Selector,
    x: Column<Advice>,
    ret: Column<Advice>,
}

impl ConditionalConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        x: Column<Advice>,
        ret: Column<Advice>,
    ) -> Self {
        meta.enable_equality(x);
        meta.enable_equality(ret);

        let config = Self {
            cond: meta.selector(),
            x,
            ret,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("condition", |meta| {
            // 1. We get x and x_inv from the column `self.x` at `cur` and `next`
            // 2. We create an expression corresponding to the boolean 1-x*x_inv
            // 3. We create an expression corresponding to 12 if x==0 and 34 if x != 0
            // 4. We impose the corresponding constrain
            let x = meta.query_advice(self.x, Rotation::cur());
            let x_inv = meta.query_advice(self.x, Rotation::next());

            let one = Expression::Constant(pallas::Base::one());
            let x_is_zero = one.clone() - x.clone() * x_inv.clone();
            let twelve = Expression::Constant(pallas::Base::from(12));
            let thirtyfour = Expression::Constant(pallas::Base::from(34));
            let poly = x_is_zero.clone() * twelve + (one.clone() - x_is_zero.clone()) * thirtyfour;

            let cond = meta.query_selector(self.cond);

            Constraints::with_selector(
                cond,
                [
                    ("12 if x=0 else 34", poly),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        // this function set the value of x, and also of x_inv, needed for the circuit
        self.cond.enable(region, offset).unwrap();

        let ret = x.value().map(|x| {
            let a = if *x == Fp::zero() {
                Fp::from(12)
            }
            else {
                Fp::from(34)
            };
            a
        });
        let ret_final = region.assign_advice(|| "ret", self.ret, offset, || ret).unwrap();
        Ok(ret_final)
    }
}

#[test]
fn test_condition_circuit() {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use crate::circuit::gadgets::assign_free_advice;


    #[derive(Default)]
    struct MyCircuit {
        x: Fp,
        output: Fp,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = (
            [Column<Advice>; 10],
            ConditionalConfig,
        );
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

            let cond_config = ConditionalConfig::configure(meta, advices[0], advices[1]);

            // let lagrange_coeffs = [
            //     meta.fixed_column(),
            //     meta.fixed_column(),
            //     meta.fixed_column(),
            //     meta.fixed_column(),
            //     meta.fixed_column(),
            //     meta.fixed_column(),
            //     meta.fixed_column(),
            //     meta.fixed_column(),
            // ];

            // let table_idx = meta.lookup_table_column();
            let constants = meta.fixed_column();
            meta.enable_constant(constants);


            (advices, cond_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, _) = config;

            // compute the output in and out of the circuit

            let x_cell = assign_free_advice(
                layouter.namespace(|| "x"),
                advices[0],
                Value::known(self.x),
            )?;

            let ret = layouter.assign_region(
                || "test simon",
                |mut region| {
                    config
                        .1
                        .assign_region(&x_cell, 0, &mut region)
                },
            )?;

            let expect_ret = if self.x == Fp::zero() {
                Value::<Fp>::known(Fp::from(12))
            } else {
                Value::<Fp>::known(Fp::from(34))
            };

            expect_ret.zip(ret.value()).map(|(a,b)| {
                assert_eq!(a, *b);
            });
            Ok(())
            
        }
    }

    let circuit = MyCircuit {
        x:Fp::one(), // this is non-zero ;-)
        output: Fp::from(34),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
