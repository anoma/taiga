use crate::com;
use crate::HashToField;
use ark_ec::{
    //short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    SWModelParameters,
    TEModelParameters,
};
use ark_ff::PrimeField;
use plonk_core::commitment::{HomomorphicCommitment, KZG10};

use ark_bls12_377::Fq;
use ark_ec::{
    short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    twisted_edwards_extended::GroupAffine as TEGroupAffine,
};
use ark_ff::{field_new, BigInteger, One};
use std::ops::Neg;

use super::validity_predicate::ValidityPredicate;

pub trait CircuitParameters: Copy {
    //               Inner Curve     Curve    Outer Curve
    // Scalar Field                    Fr         Fq
    //   Base Field      Fr            Fq

    // Curve
    type CurveScalarField: PrimeField + HashToField;
    type CurveBaseField: PrimeField + HashToField;
    type Curve: TEModelParameters<
        ScalarField = Self::CurveScalarField,
        BaseField = Self::CurveBaseField,
    >;
    // Inner curve
    type InnerCurveScalarField: PrimeField;
    type InnerCurve: TEModelParameters<
        ScalarField = Self::InnerCurveScalarField,
        BaseField = Self::CurveScalarField,
    >;
    // Outer curve
    type OuterCurveBaseField: PrimeField;
    type OuterCurve: SWModelParameters<
        ScalarField = Self::CurveBaseField,
        BaseField = Self::OuterCurveBaseField,
    >;

    type CurvePC: HomomorphicCommitment<Self::CurveScalarField>;
    type OuterCurvePC: HomomorphicCommitment<Self::CurveBaseField>;

    // F_q is the scalar field of *Curve*
    fn com_r(
        x: &Vec<Self::CurveScalarField>,
        rand: Self::CurveScalarField,
    ) -> Self::CurveScalarField {
        com(x, rand)
    }

    // F_p is the base field of *Curve*
    fn com_q(x: &Vec<Self::CurveBaseField>, rand: Self::CurveBaseField) -> Self::CurveBaseField {
        com(x, rand)
    }

    // fn get_inputs(
    //     vp: &ValidityPredicate<Self>,
    // ) -> (Vec<Self::CurveBaseField>, Vec<Self::CurveBaseField>);
}

// // We decided to continue with KZG for now.
// pub struct DLCircuitParameters {}

// impl CircuitParameters for DLCircuitParameters {
//     type CurveScalarField = ark_vesta::Fr;
//     type CurveBaseField = ark_vesta::Fq;
//     type Curve = ark_vesta::VestaParameters;
//     type InnerCurveScalarField = ark_pallas::Fr;
//     type InnerCurve = ark_pallas::PallasParameters;
//     type OuterCurveBaseField = ark_pallas::Fq;
//     type OuterCurve = ark_pallas::PallasParameters;
//     type CurvePC = IPA<SWGroupAffine<Self::Curve>, blake2::Blake2b>;
//     type OuterCurvePC = IPA<SWGroupAffine<Self::OuterCurve>, blake2::Blake2b>;
// }

#[derive(Copy, Debug, Clone)]
pub struct PairingCircuitParameters {}

impl CircuitParameters for PairingCircuitParameters {
    type CurveScalarField = ark_bls12_377::Fr;
    type CurveBaseField = ark_bls12_377::Fq;
    type Curve = ark_bls12_377::g1::Parameters;
    type InnerCurveScalarField = ark_ed_on_bls12_377::Fr;
    type InnerCurve = ark_ed_on_bls12_377::EdwardsParameters;
    type OuterCurveBaseField = ark_bw6_761::Fq;
    type OuterCurve = ark_bw6_761::g1::Parameters;
    type CurvePC = KZG10<ark_bls12_377::Bls12_377>;
    type OuterCurvePC = KZG10<ark_bw6_761::BW6_761>;

    // fn get_inputs(
    //     vp: &ValidityPredicate<Self>,
    // ) -> (Vec<Self::CurveBaseField>, Vec<Self::CurveBaseField>) {
    //     // warning! Works only for bls12_377
    //     fn ws_to_te(
    //         p: SWGroupAffine<ark_bls12_377::g1::Parameters>,
    //     ) -> TEGroupAffine<ark_bls12_377::g1::Parameters> {
    //         // values available in https://github.com/arkworks-rs/curves/blob/master/bls12_377/src/curves/g1.rs
    //         let x = p.x;
    //         let y = p.y;
    //         let alpha = -Fq::one();
    //         let s = field_new!(Fq, "10189023633222963290707194929886294091415157242906428298294512798502806398782149227503530278436336312243746741931");
    //         let sqrt_te1a = field_new!(Fq, "23560188534917577818843641916571445935985386319233886518929971599490231428764380923487987729215299304184915158756");
    //         let x_te = (x - alpha) * sqrt_te1a / y;
    //         let y_te = (s * (x - alpha) - Fq::one()) / (s * (x - alpha) + Fq::one());
    //         TEGroupAffine::<ark_bls12_377::g1::Parameters>::new(x_te, y_te)
    //     }

    //     let unblinded_qs = vec![
    //         (ws_to_te(vp.desc_vp.arithmetic.q_m.0), vp.blind_rand.q_m),
    //         (ws_to_te(vp.desc_vp.arithmetic.q_l.0), vp.blind_rand.q_l),
    //         (ws_to_te(vp.desc_vp.arithmetic.q_r.0), vp.blind_rand.q_r),
    //         (ws_to_te(vp.desc_vp.arithmetic.q_o.0), vp.blind_rand.q_o),
    //         (ws_to_te(vp.desc_vp.arithmetic.q_4.0), vp.blind_rand.q_4),
    //         (ws_to_te(vp.desc_vp.arithmetic.q_c.0), vp.blind_rand.q_c),
    //     ];

    //     // [b * Z_H + q] ?= b *[Z_H] + [q]
    //     let n = vp.ck.powers_of_g.len();
    //     let com_g_n = vp.ck.powers_of_g[n - 1];
    //     let com_g_0 = vp.ck.powers_of_g[0];
    //     let com_z_h = ws_to_te(com_g_n + com_g_0.neg());
    //     let public_inputs: Vec<Self::CurveBaseField> = vec![com_z_h.x, com_z_h.y];

    //     let mut private_inputs: Vec<Self::CurveBaseField> = vec![];
    //     for (q, b) in unblinded_qs {
    //         private_inputs.push(q.x);
    //         private_inputs.push(q.y);
    //         private_inputs.push(Self::CurveBaseField::from_le_bytes_mod_order(
    //             &b.into_repr().to_bytes_le(),
    //         ));
    //     }
    //     (private_inputs, public_inputs)
    // }
}
