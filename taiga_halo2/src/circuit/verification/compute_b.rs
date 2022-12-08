use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::{pallas, Fp};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComputeBConfig {
    q_compute_b: Selector,
    x: Column<Advice>,
    u: [Column<Advice>; 4],
}

impl ComputeBConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        x: Column<Advice>,
        u: [Column<Advice>; 4],
    ) -> Self {
        meta.enable_equality(x);
        for uu in u {
            meta.enable_equality(uu);
        }

        let config = Self {
            q_compute_b: meta.selector(),
            x,
            u,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("compute b", |meta| {
            let q_compute_b = meta.query_selector(self.q_compute_b);
            let x = meta.query_advice(self.x, Rotation::cur());
            let u: Vec<Expression<Fp>> = self
                .u
                .iter()
                .map(|uu| meta.query_advice(*uu, Rotation::cur()))
                .collect();

            let one = Expression::Constant(pallas::Base::one());
            let mut tmp = one.clone();
            let mut cur = x.clone();
            for u_j in u.iter().rev() {
                tmp = tmp * one.clone() + u_j.clone() * cur.clone();
                cur = cur.clone() * cur.clone();
            }
            meta.query_advice(self.x, Rotation::next());
            Constraints::with_selector(
                q_compute_b,
                [("", Expression::Constant(pallas::Base::zero()))],
            )
        });
    }

    pub fn assign_region(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        u: &Vec<AssignedCell<pallas::Base, pallas::Base>>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_compute_b` selector
        self.q_compute_b.enable(region, offset)?;

        // copy x and u_i into advice columns
        let x_cell = x.copy_advice(|| "x", region, self.x, offset)?;
        for (u_col, u_cell) in self.u.iter().zip(u) {
            u_cell.copy_advice(|| "u_i", region, *u_col, offset)?;
        }
        Ok(x_cell)
    }
}

#[test]
fn test_compute_b_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use ff::Field;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, Instance},
    };
    use pallas::Base as Fp;
    use rand::rngs::OsRng;

    #[derive(Default)]
    struct MyCircuit {
        x: Fp,
        u: Vec<Fp>,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = ([Column<Advice>; 10], Column<Instance>, ComputeBConfig);
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
            let instance = meta.instance_column();

            let lagrange_coeffs = [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ];
            meta.enable_constant(lagrange_coeffs[0]);

            let compute_b_config =
                ComputeBConfig::configure(meta, advices[0], advices[1..5].try_into().unwrap());

            (advices, instance, compute_b_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, instance, compute_b_config) = config;

            let x =
                assign_free_advice(layouter.namespace(|| "x"), advices[0], Value::known(self.x))?;
            let u: Vec<AssignedCell<Fp, Fp>> = self
                .u
                .iter()
                .map(|uu| {
                    assign_free_advice(layouter.namespace(|| "u_i"), advices[1], Value::known(*uu))
                        .unwrap()
                })
                .collect();

            let y = layouter.assign_region(
                || "y in cirucit",
                |mut region| compute_b_config.assign_region(&x, &u, 0, &mut region),
            )?;
            layouter.constrain_instance(y.cell(), instance, 0)?;
            Ok(())
        }
    }

    // we create random values for x, and u_i and check that the computation is okay.
    let mut rng = OsRng;
    let x = Fp::random(&mut rng);
    let u: Vec<Fp> = (0..12).map(|_| Fp::random(&mut rng)).collect();
    // compute y = $\prod\limits_{i=0}^{k-1} (1 + u_{k - 1 - i} x^{2^i})$ out-of-circuit
    let mut tmp = Fp::one();
    let mut cur = x;
    for u_j in u.iter().rev() {
        tmp *= Fp::one() + &(*u_j * &cur);
        cur *= cur;
    }
    let y = tmp;

    let circuit = MyCircuit { x, u };

    let prover = MockProver::run(11, &circuit, vec![vec![y]]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
