use halo2_proofs::{
    arithmetic::CurveExt,
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::{hashtocurve, pallas};

use super::JacobianCoordinates;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IsoMapConfig {
    q_iso_map: Selector,
    x: Column<Advice>,
    y: Column<Advice>,
    z: Column<Advice>,
}

impl IsoMapConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        x: Column<Advice>,
        y: Column<Advice>,
        z: Column<Advice>,
    ) -> Self {
        meta.enable_equality(x);
        meta.enable_equality(y);
        meta.enable_equality(z);

        let config = Self {
            q_iso_map: meta.selector(),
            x,
            y,
            z,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("iso map", |meta| {
            let q_iso_map = meta.query_selector(self.q_iso_map);
            let x = meta.query_advice(self.x, Rotation::cur());
            let y = meta.query_advice(self.y, Rotation::cur());
            let z = meta.query_advice(self.z, Rotation::cur());
            let xo = meta.query_advice(self.x, Rotation::next());
            let yo = meta.query_advice(self.y, Rotation::next());
            let zo = meta.query_advice(self.z, Rotation::next());

            let iso: Vec<Expression<pallas::Base>> = pallas::Point::ISOGENY_CONSTANTS
                .iter()
                .map(|&v| Expression::Constant(v))
                .collect();
            let z2 = z.clone().square();
            let z3 = z2.clone() * z;
            let z4 = z2.clone().square();
            let z6 = z3.clone().square();
            let num_x = ((iso[0].clone() * x.clone() + iso[1].clone() * z2.clone()) * x.clone()
                + iso[2].clone() * z4.clone())
                * x.clone()
                + iso[3].clone() * z6.clone();
            let div_x = (z2.clone() * x.clone() + iso[4].clone() * z4.clone()) * x.clone()
                + iso[5].clone() * z6.clone();

            let num_y = (((iso[6].clone() * x.clone() + iso[7].clone() * z2.clone()) * x.clone()
                + iso[8].clone() * z4.clone())
                * x.clone()
                + iso[9].clone() * z6.clone())
                * y;
            let div_y = (((x.clone() + iso[10].clone() * z2) * x.clone() + iso[11].clone() * z4)
                * x
                + iso[12].clone() * z6)
                * z3;

            let poly1 = div_x.clone() * div_y.clone() - zo.clone();
            let poly2 = num_x * div_y * zo.clone() - xo;
            let poly3 = num_y * div_x * zo.square() - yo;

            Constraints::with_selector(q_iso_map, [("z", poly1), ("x", poly2), ("y", poly3)])
        });
    }

    pub fn assign_region(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        y: &AssignedCell<pallas::Base, pallas::Base>,
        z: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<JacobianCoordinates, Error> {
        // Enable `q_iso_map` selector
        self.q_iso_map.enable(region, offset)?;
        x.copy_advice(|| "x", region, self.x, offset)?;
        y.copy_advice(|| "y", region, self.y, offset)?;
        z.copy_advice(|| "z", region, self.z, offset)?;

        let p = x
            .value()
            .zip(y.value())
            .zip(z.value())
            .map(|((&x, &y), &z)| {
                let r = pallas::Iso::new_jacobian(x, y, z).unwrap();
                let p: pallas::Point = hashtocurve::iso_map(&r, &pallas::Point::ISOGENY_CONSTANTS);
                p.jacobian_coordinates()
            });

        let xo = p.map(|p| p.0);
        let yo = p.map(|p| p.1);
        let zo = p.map(|p| p.2);

        let xo_cell = region.assign_advice(|| "xo", self.x, offset + 1, || xo)?;
        let yo_cell = region.assign_advice(|| "yo", self.y, offset + 1, || yo)?;
        let zo_cell = region.assign_advice(|| "zo", self.z, offset + 1, || zo)?;
        let result = (xo_cell, yo_cell, zo_cell);

        Ok(result)
    }
}

#[test]
fn test_map_to_curve_circuit() {
    use crate::circuit::curve::iso_map::MapToCurveConfig;
    use crate::circuit::gadgets::assign_free_advice;

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
        arithmetic::Field,
    };

    #[derive(Default)]
    struct MyCircuit {}

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = (MapToCurveConfig, [Column<Advice>; 10]);
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

            (
                MapToCurveConfig::configure(
                    meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
                    advices[6], advices[7], advices[8], advices[9],
                ),
                advices,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let u = assign_free_advice(
                layouter.namespace(|| "u"),
                config.1[0],
                Value::known(Field::zero()),
            )?;
            let ret = layouter.assign_region(
                || "map_to_curve",
                |mut region| config.0.assign_region(&u, 0, &mut region),
            )?;
            ret.0.value().map(|x| {
                assert!(
                    format!("{x:?}")
                        == "0x28c1a6a534f56c52e25295b339129a8af5f42525dea727f485ca3433519b096e"
                );
            });
            ret.1.value().map(|y| {
                assert!(
                    format!("{y:?}")
                        == "0x3bfc658bee6653c63c7d7f0927083fd315d29c270207b7c7084fa1ee6ac5ae8d"
                );
            });
            ret.2.value().map(|z| {
                assert!(
                    format!("{z:?}")
                        == "0x054b3ba10416dc104157b1318534a19d5d115472da7d746f8a5f250cd8cdef36"
                );
            });

            Ok(())
        }
    }

    let circuit = MyCircuit {};

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
