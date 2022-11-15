use ff::{Field, PrimeField};
use halo2_gadgets::{
    // ecc::chip::EccPoint,
    utilities::{bool_check, ternary},
};
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::{
    // arithmetic::CurveAffine,
    arithmetic::{CurveExt, FieldExt, SqrtRatio},
    pallas,
};
use std::marker::PhantomData;
use subtle::ConditionallySelectable;
// use subtle::ConstantTimeEq;

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

// AddChip copy from halo2 example two-chip
#[derive(Clone, Debug)]
pub struct AddChip<F: FieldExt> {
    config: AddConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct AddConfig {
    advice: [Column<Advice>; 2],
    s_add: Selector,
}

impl<F: FieldExt> Chip<F> for AddChip<F> {
    type Config = AddConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> AddChip<F> {
    pub fn construct(
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
    ) -> <Self as Chip<F>>::Config {
        let s_add = meta.selector();

        // Define our addition gate!
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (lhs + rhs - out)]
        });

        AddConfig { advice, s_add }
    }
}

pub trait AddInstructions<F: FieldExt>: Chip<F> {
    /// Returns `c = a + b`.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error>;
}

impl<F: FieldExt> AddInstructions<F> for AddChip<F> {
    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region: Region<'_, F>| {
                // We only want to use a single addition gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_add.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can compute the addition result, which is to be assigned
                // into the output position.
                let value = a.value().copied() + b.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region.assign_advice(|| "lhs + rhs", config.advice[0], 1, || value)
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapToCurveConfig {
    q_map_to_curve: Selector,
    pub u: Column<Advice>,
    pub x: Column<Advice>,
    pub y: Column<Advice>,
    u_sgn0: Column<Advice>,
    u_other_bits: Column<Advice>,
    alpha: Column<Advice>,
    beta: Column<Advice>,
    gamma: Column<Advice>,
    delta: Column<Advice>,
    epsilon: Column<Advice>,
}

impl MapToCurveConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        u: Column<Advice>,
        x: Column<Advice>,
        y: Column<Advice>,
        u_sgn0: Column<Advice>,
        u_other_bits: Column<Advice>,
        alpha: Column<Advice>,
        beta: Column<Advice>,
        gamma: Column<Advice>,
        delta: Column<Advice>,
        epsilon: Column<Advice>,
    ) -> Self {
        meta.enable_equality(u);
        meta.enable_equality(x);
        meta.enable_equality(y);

        let config = Self {
            q_map_to_curve: meta.selector(),
            u,
            x,
            y,
            u_sgn0,
            u_other_bits,
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("map to curve", |meta| {
            let q_map_to_curve = meta.query_selector(self.q_map_to_curve);
            let u = meta.query_advice(self.u, Rotation::cur());

            // alpha = inv0(ta)
            let alpha = meta.query_advice(self.alpha, Rotation::cur());
            // beta = inv0(div3)
            let beta = meta.query_advice(self.beta, Rotation::cur());
            // gamma = inv0(num_gx1)
            let gamma = meta.query_advice(self.gamma, Rotation::cur());
            let sqrt_a = meta.query_advice(self.x, Rotation::next());
            // delta = inv0(a - sqrt_a * sqrt_a)
            let delta = meta.query_advice(self.delta, Rotation::cur());
            let sqrt_b = meta.query_advice(self.y, Rotation::next());
            // epsilon = inv0(b - sqrt_b * sqrt_b)
            let epsilon = meta.query_advice(self.epsilon, Rotation::cur());

            let u_sgn0 = meta.query_advice(self.u_sgn0, Rotation::cur());
            let u_other_bits = meta.query_advice(self.u_other_bits, Rotation::cur());
            let y_sgn0 = meta.query_advice(self.u_sgn0, Rotation::next());
            let y_other_bits = meta.query_advice(self.u_other_bits, Rotation::next());

            // let x_affine = meta.query_advice(self.x, Rotation::cur());
            // let y_affine = meta.query_advice(self.y, Rotation::cur());
            let x_jac = meta.query_advice(self.x, Rotation::cur());
            let y_jac = meta.query_advice(self.y, Rotation::cur());
            let z_jac = meta.query_advice(self.u, Rotation::next());

            // 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
            // 2. x1 = (-B / A) * (1 + tv1)
            // 3. If tv1 == 0, set x1 = B / (Z * A)
            // 4. gx1 = x1^3 + A * x1 + B

            // let a = I::a();
            // let b = I::b();
            // let z_u2 = z * u.square();
            // let ta = z_u2.square() + z_u2;
            // let num_x1 = b * (ta + F::one());
            // let div = a * F::conditional_select(&-ta, &z, ta.is_zero());
            // let num2_x1 = num_x1.square();
            // let div2 = div.square();
            // let div3 = div2 * div;
            // let num_gx1 = (num2_x1 + a * div2) * num_x1 + b * div3;
            let zero = Expression::Constant(pallas::Base::zero());
            let one = Expression::Constant(pallas::Base::one());
            let a = Expression::Constant(pallas::Iso::a());
            let b = Expression::Constant(pallas::Iso::b());
            let z = Expression::Constant(pallas::Point::Z);
            let z_u2 = z.clone() * u.clone().square();
            let ta = z_u2.clone().square() + z_u2.clone();
            let num_x1 = b.clone() * (ta.clone() + one.clone());
            let ta_is_zero = one.clone() - alpha * ta.clone();
            let poly1 = ta.clone() * ta_is_zero.clone();
            let div = a.clone() * ternary(ta_is_zero, z, zero.clone() - ta);
            let num2_x1 = num_x1.clone().square();
            let div2 = div.clone().square();
            let div3 = div2.clone() * div.clone();
            let num_gx1 = (num2_x1 + a * div2) * num_x1.clone() + b * div3.clone();

            // 5. x2 = Z * u^2 * x1
            let num_x2 = z_u2.clone() * num_x1.clone();

            // 6. gx2 = x2^3 + A * x2 + B  [optimized out; see below]
            // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
            // 8. Else set x = x2 and y = sqrt(gx2)
            // sqrt_ratio(num_gx1, div3)
            // let (gx1_square, y1) = F::sqrt_ratio(&num_gx1, &div3);
            let div3_is_zero = one.clone() - div3.clone() * beta.clone();
            let poly2 = div3.clone() * div3_is_zero.clone();
            let a = beta * num_gx1.clone();
            let root_of_unity = Expression::Constant(pallas::Base::root_of_unity());
            let b = a.clone() * root_of_unity;
            let num_gx1_is_zero = one.clone() - num_gx1.clone() * gamma;
            let poly3 = num_gx1 * num_gx1_is_zero.clone();
            let a_is_sqrt_value = a - sqrt_a.clone() * sqrt_a.clone();
            let a_is_sqrt = one.clone() - a_is_sqrt_value.clone() * delta;
            let poly4 = a_is_sqrt_value * a_is_sqrt.clone();
            let b_is_sqrt_value = b - sqrt_b.clone() * sqrt_b.clone();
            let b_is_sqrt = one.clone() - b_is_sqrt_value.clone() * epsilon;
            let poly5 = b_is_sqrt_value * b_is_sqrt.clone();

            // assert!(bool::from(
            //     num_gx1_is_zero | div3_is_zero | (a_is_sqrt ^ b_is_square)
            // ));
            let two = Expression::Constant(pallas::Base::from(2));
            let a_is_square_xor_b_is_square =
                a_is_sqrt.clone() + b_is_sqrt.clone() - two.clone() * a_is_sqrt.clone() * b_is_sqrt;
            let poly6 = (one.clone() - num_gx1_is_zero.clone())
                * (one.clone() - div3_is_zero.clone())
                * (one.clone() - a_is_square_xor_b_is_square);

            // gx1_square = a_is_sqrt & !(!num_gx1_is_zero & div3_is_zero)
            let gx1_square =
                a_is_sqrt.clone() * (one.clone() - (one - num_gx1_is_zero) * div3_is_zero);
            let y1 = ternary(a_is_sqrt, sqrt_a, sqrt_b);
            let theta = Expression::Constant(pallas::Point::THETA);
            let y2 = theta * z_u2 * u.clone() * y1.clone();

            let num_x = ternary(gx1_square.clone(), num_x1, num_x2);
            let y = ternary(gx1_square, y1, y2);

            // 9. If sgn0(u) != sgn0(y), set y = -y
            let bool_check_u_sgn0 = bool_check(u_sgn0.clone());
            let bool_check_y_sgn0 = bool_check(y_sgn0.clone());
            let u_check = u - (u_other_bits * two.clone() + u_sgn0.clone());
            let y_check = y.clone() - (y_other_bits * two.clone() + y_sgn0.clone());
            let u_sgn0_xor_y_sgn0 = u_sgn0.clone() + y_sgn0.clone() - two * u_sgn0 * y_sgn0;

            // let poly7 = x_affine.clone() * div - num_x;
            // let poly8 = y_affine.clone() - ternary(u_sgn0_xor_y_sgn0, zero - y.clone(), y);
            let poly7 = x_jac - num_x * div.clone();
            let poly8 = y_jac - ternary(u_sgn0_xor_y_sgn0, zero - y.clone(), y) * div3;
            let poly9 = z_jac - div;

            // Check that (x, y) is on the curve
            // let on_curve = y_affine.square()
            //     - x_affine.clone().square() * x_affine
            //     - Expression::Constant(pallas::Affine::b());
            Constraints::with_selector(
                q_map_to_curve,
                [
                    ("ta is zero", poly1),
                    ("div3 is zero", poly2),
                    ("num_gx1 is zero", poly3),
                    ("a is sqrt", poly4),
                    ("b is sqrt", poly5),
                    (
                        "num_gx1_is_zero | div3_is_zero | (a_is_sqrt ^ b_is_square)",
                        poly6,
                    ),
                    ("bool_check_u_sgn0", bool_check_u_sgn0),
                    ("bool_check_y_sgn0", bool_check_y_sgn0),
                    ("u check", u_check),
                    ("y check", y_check),
                    ("x", poly7),
                    ("y", poly8),
                    ("z", poly9),
                    // ("on-curve", on_curve),
                ],
            )
        });
    }

    pub(super) fn assign_region(
        &self,
        u: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
        // ) -> Result<EccPoint, Error> {
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        Error,
    > {
        // Enable `q_map_to_curve` selector
        self.q_map_to_curve.enable(region, offset)?;
        u.copy_advice(|| "u", region, self.u, offset)?;

        let z = pallas::Point::Z;
        let ta = u.value().map(|u| {
            let z_u2 = z * u.square();
            z_u2.square() + z_u2
        });
        let alpha = ta.map(|ta| ta.invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(|| "alpha", self.alpha, offset, || alpha)?;

        let a = pallas::Iso::a();
        let b = pallas::Iso::b();
        let div = ta.map(|ta| a * pallas::Base::conditional_select(&-ta, &z, ta.is_zero()));
        let div3 = div.map(|div| div.square() * div);

        let beta = div3.map(|v| v.invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(|| "beta", self.beta, offset, || beta)?;

        let num_x1 = ta.map(|ta| b * (ta + pallas::Base::one()));
        let num_gx1 = num_x1
            .zip(div)
            .zip(div3)
            .map(|((num_x1, div), div3)| (num_x1.square() + a * div.square()) * num_x1 + b * div3);
        let gamma = num_gx1.map(|v| v.invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(|| "gamma", self.gamma, offset, || gamma)?;

        let a = num_gx1
            .zip(div3)
            .map(|(num, div)| div.invert().unwrap_or_else(pallas::Base::zero) * num);
        let sqrt_a = a.map(|a| a.sqrt().unwrap_or(pallas::Base::zero()));
        region.assign_advice(|| "sqrt_a", self.x, offset + 1, || sqrt_a)?;
        let delta = a.zip(sqrt_a).map(|(a, sqrt_a)| {
            (a - sqrt_a.square())
                .invert()
                .unwrap_or(pallas::Base::zero())
        });
        region.assign_advice(|| "delta", self.delta, offset, || delta)?;
        let b = a.map(|a| a * pallas::Base::root_of_unity());
        let sqrt_b = b.map(|b| b.sqrt().unwrap_or(pallas::Base::zero()));
        region.assign_advice(|| "sqrt_b", self.y, offset + 1, || sqrt_b)?;
        let epsilon = b.zip(sqrt_b).map(|(b, sqrt_b)| {
            (b - sqrt_b.square())
                .invert()
                .unwrap_or(pallas::Base::zero())
        });
        region.assign_advice(|| "epsilon", self.epsilon, offset, || epsilon)?;

        let u_sgn0 = u
            .value()
            .map(|u| pallas::Base::from((u.to_repr()[0] & 1) as u64));
        region.assign_advice(|| "u_sgn0", self.u_sgn0, offset, || u_sgn0)?;

        let u_other_bits = u
            .value()
            .zip(u_sgn0)
            .map(|(u, u_sgn0)| (u - u_sgn0) * pallas::Base::from(2).invert().unwrap());
        region.assign_advice(
            || "u_other_bits",
            self.u_other_bits,
            offset,
            || u_other_bits,
        )?;

        let theta = pallas::Point::THETA;
        let xy =
            num_gx1
                .zip(div3)
                .zip(num_x1)
                .zip(u.value())
                .map(|(((num_gx1, div3), num_x1), u)| {
                    let (gx1_square, y1) = pallas::Base::sqrt_ratio(&num_gx1, &div3);
                    let z_u2 = z * u.square();
                    let y2 = theta * z_u2 * u * y1;
                    let num_x2 = z_u2 * num_x1;
                    let num_x = pallas::Base::conditional_select(&num_x2, &num_x1, gx1_square);
                    let y = pallas::Base::conditional_select(&y2, &y1, gx1_square);
                    (num_x, y)
                });

        let y_sgn0 = xy.map(|(_, y)| pallas::Base::from((y.to_repr()[0] & 1) as u64));
        region.assign_advice(|| "y_sgn0", self.u_sgn0, offset + 1, || y_sgn0)?;

        let y_other_bits = xy
            .zip(y_sgn0)
            .map(|((_, y), y_sgn0)| (y - y_sgn0) * pallas::Base::from(2).invert().unwrap());
        region.assign_advice(
            || "y_other_bits",
            self.u_other_bits,
            offset + 1,
            || y_other_bits,
        )?;

        let x = xy.zip(div).map(|((x, _), div)| x * div);
        let y = xy.zip(div3).map(|((_, y), div3)| y * div3);
        let x = region.assign_advice(|| "x", self.x, offset, || x)?;
        let y = region.assign_advice(|| "y", self.y, offset, || y)?;
        let z = region.assign_advice(|| "z", self.u, offset + 1, || div)?;
        let result = (x, y, z);

        // let x_affine: Value<Assigned<pallas::Base>> = xy.zip(div).map(|((x, _), div)| {
        //     let x = x * div.invert().unwrap();
        //     x.into()
        // });
        // let x = region.assign_advice(|| "x_affine", self.x, offset, || x_affine)?;
        // let y_affine: Value<Assigned<pallas::Base>> = xy.zip(u.value()).map(|((_, y), u)| {
        //     let y = pallas::Base::conditional_select(&(-y), &y, u.is_odd().ct_eq(&y.is_odd()));
        //     y.into()
        // });
        // let y = region.assign_advice(|| "y_affine", self.y, offset, || y_affine)?;

        // let result = EccPoint::from_coordinates_unchecked(x, y);

        Ok(result)
    }
}

#[test]
fn test_map_to_curve_circuit() {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
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
                Value::known(pallas::Base::zero()),
            )?;
            let ret = layouter.assign_region(
                || "map_to_curve",
                |mut region| config.0.assign_region(&u, 0, &mut region),
            )?;
            ret.0.value().map(|x| {
                assert!(
                    format!("{:?}", x)
                        == "0x28c1a6a534f56c52e25295b339129a8af5f42525dea727f485ca3433519b096e"
                );
            });
            ret.1.value().map(|y| {
                assert!(
                    format!("{:?}", y)
                        == "0x3bfc658bee6653c63c7d7f0927083fd315d29c270207b7c7084fa1ee6ac5ae8d"
                );
            });
            ret.2.value().map(|z| {
                assert!(
                    format!("{:?}", z)
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
