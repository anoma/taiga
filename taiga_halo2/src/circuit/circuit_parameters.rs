use ff::{PrimeField, PrimeFieldBits};
use halo2_gadgets::poseidon::primitives::{Spec, P128Pow5T3};
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use pasta_curves::{pallas, EpAffine, EqAffine};

pub trait CircuitParameters: Copy {
    //               Inner Curve     Curve    Outer Curve
    // Scalar Field                    Fr         Fq
    //   Base Field      Fr            Fq

    // Curve
    type CurveScalarField: PrimeField + FieldExt + PrimeFieldBits;
    type PoseionParamsCurveScalarField: Spec<Self::CurveScalarField, 3, 2>;
    type CurveBaseField: PrimeField;
    type Curve: CurveAffine<Base = Self::CurveBaseField>;
    // Inner curve
    type InnerCurveScalarField: PrimeField;
    type InnerCurve: CurveAffine<Base = Self::CurveScalarField>;
    // Outer curve
    type OuterCurveBaseField: PrimeField;
    type OuterCurve: CurveAffine<Base = Self::CurveScalarField>;
}

#[derive(Copy, Debug, Clone, PartialEq)]
pub struct DLCircuitParameters {}

impl CircuitParameters for DLCircuitParameters {
    type CurveScalarField = pallas::Base;
    type PoseionParamsCurveScalarField = P128Pow5T3;
    type CurveBaseField = pallas::Scalar;
    type Curve = EqAffine;
    type InnerCurveScalarField = pallas::Scalar;
    type InnerCurve = EpAffine;
    type OuterCurveBaseField = pallas::Base;
    type OuterCurve = EpAffine;
}
