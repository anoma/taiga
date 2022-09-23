use ff::PrimeField;
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use pasta_curves::{pallas, EpAffine, EqAffine};

pub trait CircuitParameters: Copy {
    //               Inner Curve     Curve    Outer Curve
    // Scalar Field                    Fr         Fq
    //   Base Field      Fr            Fq

    // Curve
    type CurveScalarField: PrimeField+FieldExt;
    type CurveBaseField: PrimeField;
    type Curve: CurveAffine<Base=Self::CurveBaseField>;
    // Inner curve
    type InnerCurveScalarField: PrimeField;
    type InnerCurve: CurveAffine<Base=Self::CurveScalarField>;
    // Outer curve
    type OuterCurveBaseField: PrimeField;
    type OuterCurve: CurveAffine<Base=Self::CurveScalarField>;

}

#[derive(Copy, Debug, Clone)]
pub struct DLCircuitParameters {}

impl CircuitParameters for DLCircuitParameters {
    type CurveScalarField = CP::CurveScalarField;
    type CurveBaseField = CP::InnerCurveScalarField;
    type Curve = EqAffine;
    type InnerCurveScalarField = CP::InnerCurveScalarField;
    type InnerCurve = EpAffine;
    type OuterCurveBaseField = CP::CurveScalarField;
    type OuterCurve = EpAffine;
}
