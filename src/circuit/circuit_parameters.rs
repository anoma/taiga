use crate::HashToField;
use ark_ec::{
    //short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    SWModelParameters,
    TEModelParameters,
};
use ark_ff::PrimeField;
use plonk::commitment::{HomomorphicCommitment, IPA, KZG10};
use crate::{com};
use ark_ff::*;

pub trait CircuitParameters {
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
    type InnerCurveScalarField: PrimeField + HashToField;
    type InnerCurve: TEModelParameters<
        ScalarField = Self::InnerCurveScalarField,
        BaseField = Self::CurveScalarField,
    >;
    // Outer curve
    type OuterCurveBaseField: PrimeField + HashToField;
    type OuterCurve: SWModelParameters<
        ScalarField = Self::CurveBaseField,
        BaseField = Self::OuterCurveBaseField,
    >;

    type CurvePC: HomomorphicCommitment<Self::CurveScalarField>;
    type OuterCurvePC: HomomorphicCommitment<Self::CurveBaseField>;

    // F_q is the scalar field of *Curve*
    fn com_r(x: &[u8], rand: BigInteger256) -> Self::CurveScalarField {
        com(x, rand)
    }
    
    // F_p is the base field of *Curve*
    fn com_q(x: &[u8], rand: BigInteger256) -> Self::CurveBaseField {
        com(x, rand)
    }
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
}
