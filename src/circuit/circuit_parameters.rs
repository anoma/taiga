use crate::com;
use crate::HashToField;
use ark_ec::{
    //short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    SWModelParameters,
    TEModelParameters,
};
use ark_ff::PrimeField;
use ark_ff::*;
use plonk::commitment::{HomomorphicCommitment, IPA, KZG10};



pub struct Curve<E>;

pub trait CurveParameters {
    type ScalarField: PrimeField + HashToField;
    type BaseField: PrimeField + HashToField;
    type TE: TEModelParameters<
        ScalarField = Self::ScalarField,
        BaseField = Self::BaseField,
    >;

    type PC: HomomorphicCommitment<Self::ScalarField>;

    fn com_r(x: &[u8], rand: BigInteger256) -> Self::ScalarField {
        com(x, rand)
    }
    
    fn com_q(x: &[u8], rand: BigInteger256) -> Self::BaseField {
        com(x, rand)
    }
}



pub trait CircuitParameters {

    //               Inner Curve     Curve    Outer Curve
    // Scalar Field                    Fr         Fq
    //   Base Field      Fr            Fq

    type MainCurve : CurveParameters;
    type InnerCurve : CurveParameters;
    type OuterCurve : CurveParameters;
}

// // We decided to continue with KZG for now.
// pub struct DLCircuitParameters {}

// impl CircuitParameters for DLCircuitParameters {
    // type CurveScalarField = ark_vesta::Fr;
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

pub struct PairingMain;
pub struct PairingInner;
pub struct PairingOuter;

impl CurveParameters for Curve<PairingMain> {
    type ScalarField = ark_bls12_377::Fr;
    type BaseField = ark_bls12_377::Fq;
    type TE = ark_bls12_377::g1::Parameters; 
    type PC = KZG10<ark_bls12_377::Bls12_377>;
}

impl CurveParameters for Curve<PairingInner> {
    type ScalarField = ark_ed_on_bls12_377::Fr;
    type TE = ark_ed_on_bls12_377::EdwardsParameters;
}
impl CurveParameters for Curve<PairingOuter> {
    type BaseField = ark_bw6_761::Fq;
    type TE = ark_bw6_761::g1::Parameters;
    type PC = KZG10<ark_bw6_761::BW6_761>;
}

impl CircuitParameters for PairingCircuitParameters {
    type MainCurve = Curve<PairingMain>;
    type InnerCurve = Curve<PairingInner>;
    type OuterCurve = Curve<PairingOuter>;
}
