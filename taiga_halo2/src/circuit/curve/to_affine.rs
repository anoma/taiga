use pasta_curves::group::Curve;
use halo2_gadgets::ecc::{
    chip::{EccChip, EccPoint},
    Point,
};
use halo2_proofs::{
    arithmetic::{CurveAffine, CurveExt, Field},
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

use crate::constant::NoteCommitmentFixedBases;
use pasta_curves::pallas;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToAffineConfig {
    q_to_affine: Selector,
    x: Column<Advice>,
    y: Column<Advice>,
    z: Column<Advice>,
}

impl ToAffineConfig {
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
            q_to_affine: meta.selector(),
            x,
            y,
            z,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("to affine", |meta| {
            let q_to_affine = meta.query_selector(self.q_to_affine);
            let x_jacobian = meta.query_advice(self.x, Rotation::cur());
            let y_jacobian = meta.query_advice(self.y, Rotation::cur());
            let z_jacobian = meta.query_advice(self.z, Rotation::cur());
            let x_affine = meta.query_advice(self.x, Rotation::next());
            let y_affine = meta.query_advice(self.y, Rotation::next());
            let z_inv = meta.query_advice(self.z, Rotation::next());

            let zero = Expression::Constant(pallas::Base::zero());
            let one = Expression::Constant(pallas::Base::one());
            let z_is_zero = one - z_jacobian.clone() * z_inv.clone();
            let poly1 = z_jacobian * z_is_zero.clone();
            let poly2 = z_is_zero.clone() * (x_affine.clone() - zero.clone());
            let poly3 = z_is_zero.clone() * (y_affine.clone() - zero);

            let zinv2 = z_inv.clone().square();
            let poly4 = z_is_zero.clone() * (x_jacobian * zinv2.clone() - x_affine);
            let zinv3 = zinv2 * z_inv;
            let poly5 = z_is_zero * (y_jacobian * zinv3 - y_affine);

            Constraints::with_selector(
                q_to_affine,
                [
                    ("z is zero", poly1),
                    ("x: identity point", poly2),
                    ("y: identity point", poly3),
                    ("x: non-identity point", poly4),
                    ("y: non-identity point", poly5),
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        ecc_chip: EccChip<NoteCommitmentFixedBases>,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        y: &AssignedCell<pallas::Base, pallas::Base>,
        z: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
        // Enable `q_to_affine` selector
        self.q_to_affine.enable(region, offset)?;

        // copy x, y and z into the advice columns
        x.copy_advice(|| "x", region, self.x, offset)?;
        y.copy_advice(|| "y", region, self.y, offset)?;
        z.copy_advice(|| "z", region, self.z, offset)?;

        // create the corresponding affine point
        let p = x
            .value()
            .zip(y.value())
            .zip(z.value())
            .map(|((&x, &y), &z)| {
                let r = pallas::Point::new_jacobian(x, y, z)
                    .unwrap()
                    .to_affine()
                    .coordinates();
                (
                    r.map(|c| *c.x()).unwrap_or_else(pallas::Base::zero),
                    r.map(|c| *c.y()).unwrap_or_else(pallas::Base::zero),
                )
            });

        let x_affine: Value<Assigned<pallas::Base>> = p.map(|p| p.0.into());
        let y_affine: Value<Assigned<pallas::Base>> = p.map(|p| p.1.into());
        let z_inv = z
            .value()
            .map(|z| z.invert().unwrap_or(pallas::Base::zero()));

        let x_affine = region.assign_advice(|| "x_affine", self.x, offset + 1, || x_affine)?;
        let y_affine = region.assign_advice(|| "y_affine", self.y, offset + 1, || y_affine)?;
        region.assign_advice(|| "z_inv", self.z, offset + 1, || z_inv)?;
        let inner = EccPoint::from_coordinates_unchecked(x_affine, y_affine);
        let point = Point::from_inner(ecc_chip, inner);

        Ok(point)
    }
}

#[test]
fn test_to_affine_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use halo2_gadgets::{
        ecc::chip::EccConfig, utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{circuit::Layouter, dev::MockProver};
    use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
    use pallas::Base as Fp;

    #[derive(Default)]
    struct MyCircuit {
        x: Fp,
        y: Fp,
        z: Fp,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = (
            [Column<Advice>; 10],
            ToAffineConfig,
            EccConfig<NoteCommitmentFixedBases>,
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

            let table_idx = meta.lookup_table_column();

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

            let to_affine_config =
                ToAffineConfig::configure(meta, advices[0], advices[1], advices[2]);
            let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
                meta,
                advices,
                lagrange_coeffs,
                range_check,
            );
            (advices, to_affine_config, ecc_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, to_affine_config, ecc_config) = config;

            // values computed in-circuit
            let x = assign_free_advice(
                layouter.namespace(|| "x in jacobian"),
                advices[0],
                Value::known(self.x),
            )?;
            let y = assign_free_advice(
                layouter.namespace(|| "y in jacobian"),
                advices[1],
                Value::known(self.y),
            )?;
            let z = assign_free_advice(
                layouter.namespace(|| "z in jacobian"),
                advices[2],
                Value::known(self.z),
            )?;

            let ecc_chip = EccChip::construct(ecc_config);

            let point_affine_in_circuit = layouter.assign_region(
                || "point p",
                |mut region| {
                    to_affine_config.assign_region(ecc_chip.clone(), &x, &y, &z, 0, &mut region)
                },
            )?;

            // expected values out-of-circuit
            let z_inv = self.z.invert().unwrap();
            let expected_x = assign_free_advice(
                layouter.namespace(|| "x in affine"),
                advices[0],
                Value::known(self.x * z_inv * z_inv),
            )?;

            let expected_y = assign_free_advice(
                layouter.namespace(|| "y in affine"),
                advices[1],
                Value::known(self.y * z_inv * z_inv * z_inv),
            )?;

            layouter.assign_region(
                || "equality constrain for x",
                |mut region| {
                    region.constrain_equal(
                        point_affine_in_circuit.inner().x().cell(),
                        expected_x.cell(),
                    )
                },
            )?;

            layouter.assign_region(
                || "equality constrain for y",
                |mut region| {
                    region.constrain_equal(
                        point_affine_in_circuit.inner().y().cell(),
                        expected_y.cell(),
                    )
                },
            )?;

            Ok(())
        }
    }

    // point obtained from the sagemath script `test_jac_to_aff.sage`
    let p_x = Fp::from_raw([
        13784059110835783298,
        13807755342919275192,
        3618717831429396609,
        1306551583783509020,
    ]);
    let p_y = Fp::from_raw([
        14781862750826647704,
        16534633030322374533,
        6389784117114317226,
        3663091467811893796,
    ]);
    let p_z = Fp::from_raw([
        10342000130445668299,
        14301925621303361780,
        15264636510351389875,
        6027681381599967,
    ]);

    let circuit = MyCircuit {
        x: p_x,
        y: p_y,
        z: p_z,
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
