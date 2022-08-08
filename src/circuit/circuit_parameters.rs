use crate::constant::{ACTION_KEY, BLIND_VP_KEY, OPC_SETUP_MAP, PC_SETUP_MAP};
use crate::utils::ws_to_te;
use ark_ec::{
    //short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    SWModelParameters,
    TEModelParameters,
};
//use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::commitment::{HomomorphicCommitment, KZG10};
use plonk_core::proof_system::{ProverKey, VerifierKey};
use std::ops::Neg;

use ff::PrimeField;
use pasta_curves::{pallas, vesta};


pub trait CircuitParameters: Copy {
    //               Inner Curve     Curve    Outer Curve
    // Scalar Field                    Fr         Fq
    //   Base Field      Fr            Fq

    // Curve
    type CurveScalarField: PrimeField;
    type CurveBaseField: PrimeField;
    
    type Curve: group::Curve;
    
    // Inner curve
    type InnerCurveScalarField: PrimeField;
    type InnerCurve: group::Curve;
    // Outer curve
    type OuterCurveBaseField: PrimeField;
    type OuterCurve: group::Curve;
/* 
    type CurvePC: HomomorphicCommitment<Self::CurveScalarField>;
    type OuterCurvePC: HomomorphicCommitment<Self::CurveBaseField>;

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

    fn get_pc_setup_params<'staitc>(
        circuit_size: usize,
    ) -> &'staitc <Self::CurvePC as PolynomialCommitment<
        Self::CurveScalarField,
        DensePolynomial<Self::CurveScalarField>,
    >>::UniversalParams;

    fn get_opc_setup_params<'staitc>(
        circuit_size: usize,
    ) -> &'staitc <Self::OuterCurvePC as PolynomialCommitment<
        Self::CurveBaseField,
        DensePolynomial<Self::CurveBaseField>,
    >>::UniversalParams;

    fn get_action_pk<'staitc>() -> &'staitc ProverKey<Self::CurveScalarField>;
    fn get_action_vk<'staitc>() -> &'staitc VerifierKey<Self::CurveScalarField, Self::CurvePC>;
    fn get_blind_vp_pk<'staitc>() -> &'staitc ProverKey<Self::CurveBaseField>;
    fn get_blind_vp_vk<'staitc>() -> &'staitc VerifierKey<Self::CurveBaseField, Self::OuterCurvePC>;
*/
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
pub struct HaloCircuitParameters {}

impl CircuitParameters for HaloCircuitParameters {
    type CurveScalarField = vesta::Scalar;
    type CurveBaseField = vesta::Base;
    type Curve = vesta::Affine;
    type InnerCurveScalarField = pallas::Scalar;
    type InnerCurve = pallas::Affine;
    type OuterCurveBaseField = pallas::Base;
    type OuterCurve = pallas::Affine;
    /*
    type CurvePC = KZG10<ark_bls12_381_new::Bls12_381New>;
    type OuterCurvePC = KZG10<ark_bw6_764_new::BW6_764New>;

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
        let n = ck.powers_of_g.len();
        let com_g_n = ck.powers_of_g[n - 1];
        let com_g_0 = ck.powers_of_g[0];
        let ws_com_zh = com_g_n + com_g_0.neg();
        let com_z_h = ws_to_te(ws_com_zh);
        [com_z_h.x, com_z_h.y]
    }

    fn get_pc_setup_params<'staitc>(
        circuit_size: usize,
    ) -> &'staitc <Self::CurvePC as PolynomialCommitment<
        Self::CurveScalarField,
        DensePolynomial<Self::CurveScalarField>,
    >>::UniversalParams {
        PC_SETUP_MAP.get(&circuit_size).unwrap()
    }

    fn get_opc_setup_params<'staitc>(
        circuit_size: usize,
    ) -> &'staitc <Self::OuterCurvePC as PolynomialCommitment<
        Self::CurveBaseField,
        DensePolynomial<Self::CurveBaseField>,
    >>::UniversalParams {
        OPC_SETUP_MAP.get(&circuit_size).unwrap()
    }

    fn get_action_pk<'staitc>() -> &'staitc ProverKey<Self::CurveScalarField> {
        &ACTION_KEY.0
    }
    fn get_action_vk<'staitc>() -> &'staitc VerifierKey<Self::CurveScalarField, Self::CurvePC> {
        &ACTION_KEY.1
    }
    fn get_blind_vp_pk<'staitc>() -> &'staitc ProverKey<Self::CurveBaseField> {
        &BLIND_VP_KEY.0
    }
    fn get_blind_vp_vk<'staitc>() -> &'staitc VerifierKey<Self::CurveBaseField, Self::OuterCurvePC>
    {
        &BLIND_VP_KEY.1
    }
    */
}
