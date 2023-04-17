use halo2_gadgets::utilities::{bool_check, ternary};
use halo2_proofs::{
    arithmetic::CurveExt,
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;
use halo2_proofs::arithmetic::Field;
use pasta_curves::group::ff::PrimeField;
use subtle::{ConditionallySelectable, ConstantTimeEq};

use super::JacobianCoordinates;

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
        // following https://github.com/zcash/pasta_curves/blob/1bd803d57b83d1efbe2ce7c307d00a2ce2c4f1cf/src/hashtocurve.rs:
        // 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
        // 2. x1 = (-B / A) * (1 + tv1)
        // 3. If tv1 == 0, set x1 = B / (Z * A)
        // 4. gx1 = x1^3 + A * x1 + B
        // 5. x2 = Z * u^2 * x1
        // 6. gx2 = x2^3 + A * x2 + B
        // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
        // 8. Else set x = x2 and y = sqrt(gx2)
        // 9. If sgn0(u) != sgn0(y), set y = -y

        meta.create_gate("map to curve", |meta| {
            let q_map_to_curve = meta.query_selector(self.q_map_to_curve);
            let u = meta.query_advice(self.u, Rotation::cur());

            // for the condition ta.is_zero()
            // alpha = inv0(ta)
            let alpha = meta.query_advice(self.alpha, Rotation::cur());
            // ta = zu²(1+zu²)
            let ta = meta.query_advice(self.alpha, Rotation::next());

            // for the division by div3
            // beta = inv0(div3)
            let beta = meta.query_advice(self.beta, Rotation::cur());

            // for the is_square condition
            let gx1_square = meta.query_advice(self.epsilon, Rotation::next());

            // square roots
            // we store sqrt(x) in an advice. In order to check it in a constrain, we need an additional is_zero condition for a-sqrta² == 0
            // so we store 1/(a-sqrta²).
            // for the sqrt of a
            let sqrt_a = meta.query_advice(self.x, Rotation::next());
            // delta = inv0(a - sqrt_a * sqrt_a)
            let delta = meta.query_advice(self.delta, Rotation::cur());
            // for the sqrt of b
            let sqrt_b = meta.query_advice(self.y, Rotation::next());
            // epsilon = inv0(b - sqrt_b * sqrt_b)
            let epsilon = meta.query_advice(self.epsilon, Rotation::cur());

            // num_x1 = b(ta+1)
            let num_x1 = meta.query_advice(self.beta, Rotation::next());
            let div = meta.query_advice(self.gamma, Rotation::next());
            let num_gx1 = meta.query_advice(self.delta, Rotation::next());

            // gamma = inv0(num_gx1)
            let gamma = meta.query_advice(self.gamma, Rotation::cur());

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
            let ta_poly = z_u2.clone().square() + z_u2.clone() - ta.clone();
            let num_x1_poly = b.clone() * (ta.clone() + one.clone()) - num_x1.clone();
            let ta_is_zero = one.clone() - alpha * ta.clone();
            let poly1 = ta.clone() * ta_is_zero.clone();
            let div_poly = a.clone() * ternary(ta_is_zero, z, zero.clone() - ta) - div.clone();
            let num2_x1 = num_x1.clone().square();
            let div2 = div.clone().square();
            let div3 = div2.clone() * div.clone();
            let num_gx1_poly =
                (num2_x1 + a * div2) * num_x1.clone() + b * div3.clone() - num_gx1.clone();

            // 5. x2 = Z * u^2 * x1
            let num_x2 = z_u2.clone() * num_x1.clone();

            // 6. gx2 = x2^3 + A * x2 + B  [optimized out; see below]
            // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
            // 8. Else set x = x2 and y = sqrt(gx2)
            // sqrt_ratio(num_gx1, div3)
            // let (gx1_square, y1) = F::sqrt_ratio(&num_gx1, &div3);
            let div3_is_zero = one.clone() - div3.clone() * beta.clone();
            let poly2 = div3.clone() * div3_is_zero.clone();
            let a = beta.clone() * num_gx1.clone();
            let root_of_unity = Expression::Constant(pallas::Base::ROOT_OF_UNITY);
            let b = a.clone() * root_of_unity;
            let num_gx1_is_zero = one.clone() - num_gx1.clone() * gamma.clone();
            let poly3 = num_gx1.clone() * num_gx1_is_zero.clone();
            // sqrt a
            let a_is_sqrt_value = a - sqrt_a.clone() * sqrt_a.clone();
            let a_is_sqrt = one.clone() - a_is_sqrt_value.clone() * delta;
            let poly4 = a_is_sqrt_value * a_is_sqrt.clone();
            // sqrt b
            let b_is_sqrt_value = b - sqrt_b.clone() * sqrt_b.clone();
            let b_is_sqrt = one.clone() - b_is_sqrt_value.clone() * epsilon;
            let poly5 = b_is_sqrt_value * b_is_sqrt.clone();

            // assert!(bool::from(
            //     num_gx1_is_zero | div3_is_zero | (a_is_sqrt ^ b_is_square)
            // ));
            let two = Expression::Constant(pallas::Base::from(2));
            let a_is_square_xor_b_is_square =
                a_is_sqrt.clone() + b_is_sqrt.clone() - two.clone() * a_is_sqrt.clone() * b_is_sqrt;
            let poly6 = (num_gx1 * gamma)
                * (div3.clone() * beta)
                * (one.clone() - a_is_square_xor_b_is_square);

            // gx1_square = a_is_sqrt & !(!num_gx1_is_zero & div3_is_zero)
            let gx1_square_poly = a_is_sqrt.clone()
                * (one.clone() - (one - num_gx1_is_zero) * div3_is_zero)
                - gx1_square.clone();
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
                    ("ta", ta_poly),
                    ("num_x1", num_x1_poly),
                    ("div", div_poly),
                    ("div3 is zero", poly2),
                    ("num_gx1", num_gx1_poly),
                    ("num_gx1 is zero", poly3),
                    ("a is sqrt", poly4),
                    ("b is sqrt", poly5),
                    ("gx1_square", gx1_square_poly),
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
        region.assign_advice(|| "ta", self.alpha, offset + 1, || ta)?;

        let a = pallas::Iso::a();
        let b = pallas::Iso::b();
        let div = ta.map(|ta| a * pallas::Base::conditional_select(&-ta, &z, ta.is_zero()));
        region.assign_advice(|| "div", self.gamma, offset + 1, || div)?;
        let div3 = div.map(|div| div.square() * div);

        let beta = div3.map(|v| v.invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(|| "beta", self.beta, offset, || beta)?;

        let num_x1 = ta.map(|ta| b * (ta + pallas::Base::one()));
        region.assign_advice(|| "num_x1", self.beta, offset + 1, || num_x1)?;
        let num_gx1 = num_x1
            .zip(div)
            .zip(div3)
            .map(|((num_x1, div), div3)| (num_x1.square() + a * div.square()) * num_x1 + b * div3);
        region.assign_advice(|| "num_gx1", self.delta, offset + 1, || num_gx1)?;
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
        let b = a.map(|a| a * pallas::Base::ROOT_OF_UNITY);
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
                    (gx1_square, num_x, y)
                });

        let gx1_square = xy.map(|(gx1_square, _, _)| pallas::Base::from(bool::from(gx1_square)));
        region.assign_advice(|| "gx1_square", self.epsilon, offset + 1, || gx1_square)?;

        let y_sgn0 = xy.map(|(_, _, y)| pallas::Base::from((y.to_repr()[0] & 1) as u64));
        region.assign_advice(|| "y_sgn0", self.u_sgn0, offset + 1, || y_sgn0)?;

        let y_other_bits = xy
            .zip(y_sgn0)
            .map(|((_, _, y), y_sgn0)| (y - y_sgn0) * pallas::Base::from(2).invert().unwrap());
        region.assign_advice(
            || "y_other_bits",
            self.u_other_bits,
            offset + 1,
            || y_other_bits,
        )?;

        let x = xy.zip(div).map(|((_, x, _), div)| x * div);
        let y = xy.zip(div3).zip(u.value()).map(|(((_, _, y), div3), u)| {
            let y = pallas::Base::conditional_select(&(-y), &y, u.is_odd().ct_eq(&y.is_odd()));
            y * div3
        });
        let x = region.assign_advice(|| "x", self.x, offset, || x)?;
        let y = region.assign_advice(|| "y", self.y, offset, || y)?;
        let z = region.assign_advice(|| "z", self.u, offset + 1, || div)?;
        Ok((x, y, z))
    }
}

// Write a test for iso map?
