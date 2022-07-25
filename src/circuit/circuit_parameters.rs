use crate::com;
use crate::utils::ws_to_te;
use crate::HashToField;
use ark_ec::{
    //short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    SWModelParameters,
    TEModelParameters,
};
use ark_ff::{BigInteger, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::commitment::{HomomorphicCommitment, KZG10};
use plonk_core::proof_system::{Blinding, VerifierKey};
use std::ops::Neg;

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

    fn get_inputs(
        desc_vp: &VerifierKey<Self::CurveScalarField, Self::CurvePC>,
        ck: &<Self::CurvePC as PolynomialCommitment<
            Self::CurveScalarField,
            DensePolynomial<Self::CurveScalarField>,
        >>::CommitterKey,
        blind: &Blinding<Self::CurveScalarField>,
    ) -> (Vec<Self::CurveBaseField>, [Self::CurveBaseField; 2]);
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
    type CurveScalarField = ark_bls12_381_new::Fr;
    type CurveBaseField = ark_bls12_381_new::Fq;
    type Curve = ark_bls12_381_new::g1::Parameters;
    type InnerCurveScalarField = ark_ed_on_bls12_381_new::Fr;
    type InnerCurve = ark_ed_on_bls12_381_new::Parameters;
    type OuterCurveBaseField = ark_bw6_764_new::Fq;
    type OuterCurve = ark_bw6_764_new::g1::Parameters;
    type CurvePC = KZG10<ark_bls12_381_new::Bls12_381New>;
    type OuterCurvePC = KZG10<ark_bw6_764_new::BW6_764New>;

    fn get_inputs(
        desc_vp: &VerifierKey<Self::CurveScalarField, Self::CurvePC>,
        ck: &<Self::CurvePC as PolynomialCommitment<
            Self::CurveScalarField,
            DensePolynomial<Self::CurveScalarField>,
        >>::CommitterKey,
        blind: &Blinding<Self::CurveScalarField>,
    ) -> (Vec<Self::CurveBaseField>, [Self::CurveBaseField; 2]) {
        let unblinded_qs = vec![
            (ws_to_te(desc_vp.arithmetic.q_m.0), blind.q_m),
            (ws_to_te(desc_vp.arithmetic.q_l.0), blind.q_l),
            (ws_to_te(desc_vp.arithmetic.q_r.0), blind.q_r),
            (ws_to_te(desc_vp.arithmetic.q_o.0), blind.q_o),
            (ws_to_te(desc_vp.arithmetic.q_4.0), blind.q_4),
            (ws_to_te(desc_vp.arithmetic.q_c.0), blind.q_c),
        ];

        // [b * Z_H + q] ?= b *[Z_H] + [q]
        let n = ck.powers_of_g.len();
        let com_g_n = ck.powers_of_g[n - 1];
        let com_g_0 = ck.powers_of_g[0];
        let com_z_h = ws_to_te(com_g_n + com_g_0.neg());
        let public_inputs = [com_z_h.x, com_z_h.y];

        let mut private_inputs: Vec<Self::CurveBaseField> = vec![];
        for (q, b) in unblinded_qs {
            private_inputs.push(q.x);
            private_inputs.push(q.y);
            private_inputs.push(Self::CurveBaseField::from_le_bytes_mod_order(
                &b.into_repr().to_bytes_le(),
            ));
        }
        (private_inputs, public_inputs)
    }
}
