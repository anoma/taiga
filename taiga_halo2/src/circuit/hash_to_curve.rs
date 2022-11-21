use crate::constant::NoteCommitmentFixedBases;
use ff::{Field, PrimeField};
use group::Curve;
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccPoint},
        Point,
    },
    utilities::{bool_check, ternary},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::{
    arithmetic::CurveAffine,
    arithmetic::{CurveExt, SqrtRatio},
    hashtocurve, pallas,
};
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;
// use std::marker::PhantomData;

type JacobianCoordinates = (
    AssignedCell<pallas::Base, pallas::Base>,
    AssignedCell<pallas::Base, pallas::Base>,
    AssignedCell<pallas::Base, pallas::Base>,
);

// TODO: make HashToCurve a chip
// pub trait HashToCurveInstructions<F: FieldExt>: Chip<F> {
//     type Var;
//     fn hash_to_curve(
//         &self,
//         layouter: impl Layouter<F>,
//         messages: &[Self::Var],
//     ) -> Result<(), Error>;
// }

// #[derive(Clone, Debug)]
// pub struct HashToCurveChip<F: FieldExt> {
//     config: HashToCurveConfig,
//     _marker: PhantomData<F>,
// }

// impl<F: FieldExt> Chip<F> for HashToCurveChip<F> {
//     type Config = HashToCurveConfig;
//     type Loaded = ();

//     fn config(&self) -> &Self::Config {
//         &self.config
//     }

//     fn loaded(&self) -> &Self::Loaded {
//         &()
//     }
// }

// impl<F: FieldExt> HashToCurveInstructions<F> for HashToCurveChip<F> {
//     type Var = AssignedCell<F, F>;
//     fn hash_to_curve(
//         &self,
//         mut layouter: impl Layouter<F>,
//         messages: &[Self::Var],
//     ) -> Result<(), Error> {
//         Ok(())
//     }
// }

pub fn hash_to_curve_circuit(
    mut layouter: impl Layouter<pallas::Base>,
    config: HashToCurveConfig,
    messages: &[AssignedCell<pallas::Base, pallas::Base>],
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
) -> Result<Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
    // TODO: add hash circuit
    // Use messages as u_0 and u_1
    let q_0 = layouter.assign_region(
        || "u_0 map_to_curve",
        |mut region| {
            config
                .map_to_curve_config
                .assign_region(&messages[0], 0, &mut region)
        },
    )?;

    let r_0 = layouter.assign_region(
        || "q_0 isogeny map",
        |mut region| {
            config
                .iso_map_config
                .assign_region(&q_0.0, &q_0.1, &q_0.2, 0, &mut region)
        },
    )?;

    let k_0 = layouter.assign_region(
        || "r_0 to affine",
        |mut region| {
            config.to_affine_config.assign_region(
                ecc_chip.clone(),
                &r_0.0,
                &r_0.1,
                &r_0.2,
                0,
                &mut region,
            )
        },
    )?;

    let q_1 = layouter.assign_region(
        || "u_1 map_to_curve",
        |mut region| {
            config
                .map_to_curve_config
                .assign_region(&messages[1], 0, &mut region)
        },
    )?;

    let r_1 = layouter.assign_region(
        || "q_1 isogeny map",
        |mut region| {
            config
                .iso_map_config
                .assign_region(&q_1.0, &q_1.1, &q_1.2, 0, &mut region)
        },
    )?;

    let k_1 = layouter.assign_region(
        || "r_1 to affine",
        |mut region| {
            config.to_affine_config.assign_region(
                ecc_chip.clone(),
                &r_1.0,
                &r_1.1,
                &r_1.2,
                0,
                &mut region,
            )
        },
    )?;

    k_0.add(layouter.namespace(|| "k_0 + k_1"), &k_1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashToCurveConfig {
    // TODO: add hash config
    map_to_curve_config: MapToCurveConfig,
    iso_map_config: IsoMapConfig,
    to_affine_config: ToAffineConfig,
}

impl HashToCurveConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
    ) -> Self {
        let map_to_curve_config = MapToCurveConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
            advices[6], advices[7], advices[8], advices[9],
        );
        let iso_map_config = IsoMapConfig::configure(meta, advices[0], advices[1], advices[2]);
        let to_affine_config = ToAffineConfig::configure(meta, advices[3], advices[4], advices[5]);

        Self {
            map_to_curve_config,
            iso_map_config,
            to_affine_config,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapToCurveConfig {
    q_map_to_curve: Selector,
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

            let x_jac = meta.query_advice(self.x, Rotation::cur());
            let y_jac = meta.query_advice(self.y, Rotation::cur());
            let z_jac = meta.query_advice(self.u, Rotation::next());

            // 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
            // 2. x1 = (-B / A) * (1 + tv1)
            // 3. If tv1 == 0, set x1 = B / (Z * A)
            // 4. gx1 = x1^3 + A * x1 + B

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

            let poly7 = x_jac - num_x * div.clone();
            let poly8 = y_jac - ternary(u_sgn0_xor_y_sgn0, zero - y.clone(), y) * div3;
            let poly9 = z_jac - div;

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
                ],
            )
        });
    }

    pub fn assign_region(
        &self,
        u: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<JacobianCoordinates, Error> {
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
        let y = xy.zip(div3).zip(u.value()).map(|(((_, y), div3), u)| {
            let y = pallas::Base::conditional_select(&(-y), &y, u.is_odd().ct_eq(&y.is_odd()));
            y * div3
        });
        let x = region.assign_advice(|| "x", self.x, offset, || x)?;
        let y = region.assign_advice(|| "y", self.y, offset, || y)?;
        let z = region.assign_advice(|| "z", self.u, offset + 1, || div)?;
        Ok((x, y, z))
    }
}

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
        x.copy_advice(|| "x", region, self.x, offset)?;
        y.copy_advice(|| "y", region, self.y, offset)?;
        z.copy_advice(|| "z", region, self.z, offset)?;

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
fn test_hash_to_curve_circuit() {
    use halo2_gadgets::{
        ecc::chip::EccConfig, utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };

    use crate::circuit::gadgets::assign_free_advice;

    #[derive(Default)]
    struct MyCircuit {}

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = (
            [Column<Advice>; 10],
            HashToCurveConfig,
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

            let hash_to_curve_config = HashToCurveConfig::configure(meta, advices);

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

            let table_idx = meta.lookup_table_column();
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

            let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
                meta,
                advices,
                lagrange_coeffs,
                range_check,
            );

            (advices, hash_to_curve_config, ecc_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, hash_to_curve_config, ecc_config) = config;
            let ecc_chip = EccChip::construct(ecc_config);

            let input_message = [0u8; 32];
            let mut us = [Field::zero(); 2];
            // TODO: add hash circuit here
            hashtocurve::sha256_to_field("pallas", "taiga:value_base", &input_message, &mut us);
            let u_0 = assign_free_advice(
                layouter.namespace(|| "u_0"),
                advices[0],
                Value::known(us[0]),
            )?;
            let u_1 = assign_free_advice(
                layouter.namespace(|| "u_1"),
                advices[1],
                Value::known(us[1]),
            )?;
            let messages = vec![u_0, u_1];
            let ret = hash_to_curve_circuit(
                layouter.namespace(|| "hash to curve"),
                hash_to_curve_config,
                &messages,
                ecc_chip.clone(),
            )?;
            let expect_ret = {
                let hash = pallas::Point::sha256_to_curve("taiga:value_base");
                let expect_point = hash(&input_message);
                Point::new(
                    ecc_chip,
                    layouter.namespace(|| "expect_point"),
                    Value::known(expect_point.to_affine()),
                )
            }?;
            ret.constrain_equal(layouter, &expect_ret)
        }
    }

    let circuit = MyCircuit {};

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}

#[test]
fn test_map_to_curve_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
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
                Value::known(Field::zero()),
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
