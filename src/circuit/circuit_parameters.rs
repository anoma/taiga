use crate::com;
use crate::utils::ws_to_te;
use crate::HashToField;
use ark_ec::{
    //short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    SWModelParameters,
    TEModelParameters,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::commitment::{HomomorphicCommitment, KZG10};
use plonk_core::proof_system::VerifierKey;
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

    fn pack_vk(
        vk: &VerifierKey<Self::CurveScalarField, Self::CurvePC>,
    ) -> Vec<Self::CurveBaseField>;

    fn get_zh(
        vp_setup: &<Self::CurvePC as PolynomialCommitment<
            Self::CurveScalarField,
            DensePolynomial<Self::CurveScalarField>,
        >>::UniversalParams,
        vp_circuit_size: usize,
    ) -> [Self::CurveBaseField; 2];
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

    fn pack_vk(
        vk: &VerifierKey<Self::CurveScalarField, Self::CurvePC>,
    ) -> Vec<Self::CurveBaseField> {
        let com_vec = vec![
            ws_to_te(vk.arithmetic.q_m.0),
            ws_to_te(vk.arithmetic.q_l.0),
            ws_to_te(vk.arithmetic.q_r.0),
            ws_to_te(vk.arithmetic.q_o.0),
            ws_to_te(vk.arithmetic.q_4.0),
            ws_to_te(vk.arithmetic.q_c.0),
            ws_to_te(vk.arithmetic.q_arith.0),
            ws_to_te(vk.range_selector_commitment.0),
            ws_to_te(vk.logic_selector_commitment.0),
            ws_to_te(vk.fixed_group_add_selector_commitment.0),
            ws_to_te(vk.variable_group_add_selector_commitment.0),
            ws_to_te(vk.permutation.left_sigma.0),
            ws_to_te(vk.permutation.right_sigma.0),
            ws_to_te(vk.permutation.out_sigma.0),
            ws_to_te(vk.permutation.fourth_sigma.0),
            ws_to_te(vk.lookup.q_lookup.0),
            ws_to_te(vk.lookup.table_1.0),
            ws_to_te(vk.lookup.table_2.0),
            ws_to_te(vk.lookup.table_3.0),
            ws_to_te(vk.lookup.table_4.0),
        ];

        let mut ret = vec![];
        com_vec.into_iter().for_each(|v| {
            ret.push(v.x);
            ret.push(v.y);
        });
        ret
    }

    fn get_zh(
        vp_setup: &<Self::CurvePC as PolynomialCommitment<
            Self::CurveScalarField,
            DensePolynomial<Self::CurveScalarField>,
        >>::UniversalParams,
        vp_circuit_size: usize,
    ) -> [Self::CurveBaseField; 2] {
        let (ck, _) = Self::CurvePC::trim(vp_setup, vp_circuit_size, 0, None).unwrap();

        // [b * Z_H + q] ?= b *[Z_H] + [q]
        let n = ck.powers_of_g.len();
        let com_g_n = ck.powers_of_g[n - 1];
        let com_g_0 = ck.powers_of_g[0];
        let com_z_h = ws_to_te(com_g_n + com_g_0.neg());
        [com_z_h.x, com_z_h.y]
    }
}
