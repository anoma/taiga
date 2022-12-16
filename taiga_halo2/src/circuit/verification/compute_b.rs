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
    y: Column<Advice>,
}

impl ComputeBConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        x: Column<Advice>,
        u: [Column<Advice>; 4],
        y: Column<Advice>,
    ) -> Self {
        meta.enable_equality(x);
        for uu in u {
            meta.enable_equality(uu);
        }
        meta.enable_equality(y);

        let config = Self {
            q_compute_b: meta.selector(),
            x,
            u,
            y,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("compute b", |meta| {
            let q_compute_b = meta.query_selector(self.q_compute_b);
            let x = meta.query_advice(self.x, Rotation::cur());
            let mut u_array: Vec<Vec<Expression<Fp>>> = vec![];
            /*
            We collect the u values stored as follows:
            u0    u4    u8    u12
            u1    u5    u9    u13
            u2    u6    u10   u14
            u3    u7    u11   u15
            */

            for uu in self.u {
                let mut u_col = vec![];
                u_col.push(meta.query_advice(uu, Rotation(0)));
                u_col.push(meta.query_advice(uu, Rotation(1)));
                u_col.push(meta.query_advice(uu, Rotation(2)));
                u_col.push(meta.query_advice(uu, Rotation(3)));
                u_array.push(u_col);
            }
            let y = meta.query_advice(self.y, Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let mut tmp = one.clone();
            let mut cur = x.clone();
            for u_col in u_array.iter().rev() {
                for u_j in u_col.iter().rev() {
                    tmp = tmp * (one.clone() + u_j.clone() * cur.clone());
                    cur = cur.square();
                }
            }

            Constraints::with_selector(q_compute_b, [("y computation", tmp.clone() - y)])
        });
    }

    pub fn assign_region(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        u: &Vec<AssignedCell<pallas::Base, pallas::Base>>,
        y: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Enable `q_compute_b` selector
        self.q_compute_b.enable(region, offset)?;

        // copy x and u_i into advice columns
        x.copy_advice(|| "x", region, self.x, offset)?;
        // we use four columns for the u_i, and store four in each (4 * 8 == 32)
        for (u_col, u_4cells) in self.u.iter().zip(u.chunks(4)) {
            let mut i = offset;
            for u_cell in u_4cells {
                u_cell.copy_advice(|| "u_i", region, *u_col, i)?;
                i = i + 1;
            }
        }
        Ok(y.copy_advice(|| "y", region, self.y, offset)?)
    }
}

#[test]
fn test_compute_b_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use ff::Field;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::Circuit,
    };
    use pallas::Base as Fp;
    use rand::rngs::OsRng;

    #[derive(Default)]
    struct MyCircuit {
        x: Fp,
        u: [Fp; 16],
        y: Fp,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = ([Column<Advice>; 10], ComputeBConfig);
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
            let compute_b_config = ComputeBConfig::configure(
                meta,
                advices[0],
                advices[1..5].try_into().unwrap(),
                advices[5],
            );
            (advices, compute_b_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, compute_b_config) = config;

            let x =
                assign_free_advice(layouter.namespace(|| "x"), advices[0], Value::known(self.x))?;
            let mut i = 1; // advice columns are columns 1 to 4
            let mut cpt = 0;
            let mut u_vec: Vec<AssignedCell<Fp, Fp>> = vec![];
            for uu in self.u.iter() {
                // assign a region for uu
                let u_cell = assign_free_advice(
                    layouter.namespace(|| "u_i"),
                    advices[i],
                    Value::known(*uu),
                )?;
                u_vec.push(u_cell);
                cpt = cpt + 1;
                if cpt == 4 {
                    i = i + 1;
                    cpt = 0;
                }
            }
            let y =
                assign_free_advice(layouter.namespace(|| "y"), advices[i], Value::known(self.y))?;

            let y_in = layouter.assign_region(
                || "y in cirucit",
                |mut region| compute_b_config.assign_region(&x, &u_vec, &y, 0, &mut region),
            )?;

            layouter.assign_region(
                || "equality constrain for y",
                |mut region| region.constrain_equal(y_in.cell(), y.cell()),
            )?;
            Ok(())
        }
    }

    // we create random values for x, and u_i and check that the computation is okay.
    let mut rng = OsRng;
    let x = Fp::random(&mut rng);
    let u = [Fp::random(&mut rng); 16];
    // compute y = $\prod\limits_{i=0}^{k-1} (1 + u_{k - 1 - i} x^{2^i})$ out-of-circuit
    let mut tmp = Fp::one();
    let mut cur = x;
    for u_j in u.iter().rev() {
        tmp *= Fp::one() + &(*u_j * &cur);
        cur *= cur;
    }
    let y = tmp;

    let circuit = MyCircuit { x, u, y };

    let prover = MockProver::run(6, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
