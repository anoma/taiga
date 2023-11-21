use crate::constant::RESOURCE_COMMITMENT_R_GENERATOR;
use crate::resource::Resource;
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::group::cofactor::CofactorCurveAffine;
use pasta_curves::group::{Curve, Group, GroupEncoding};
use pasta_curves::pallas;
#[cfg(feature = "nif")]
use rustler::NifTuple;
use subtle::CtOption;

#[cfg(feature = "serde")]
use serde;

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "nif", derive(NifTuple))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValueCommitment(pallas::Point);

impl ValueCommitment {
    pub fn commit(
        input_resource: &Resource,
        output_resource: &Resource,
        blind_r: &pallas::Scalar,
    ) -> Self {
        let base_input = input_resource.get_kind();
        let base_output = output_resource.get_kind();
        ValueCommitment(
            base_input * pallas::Scalar::from(input_resource.value)
                - base_output * pallas::Scalar::from(output_resource.value)
                + RESOURCE_COMMITMENT_R_GENERATOR.to_curve() * blind_r,
        )
    }

    pub fn get_x(&self) -> pallas::Base {
        if self.0 == pallas::Point::identity() {
            pallas::Base::zero()
        } else {
            *self.0.to_affine().coordinates().unwrap().x()
        }
    }

    pub fn get_y(&self) -> pallas::Base {
        if self.0 == pallas::Point::identity() {
            pallas::Base::zero()
        } else {
            *self.0.to_affine().coordinates().unwrap().y()
        }
    }

    pub fn inner(&self) -> pallas::Point {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<ValueCommitment> {
        pallas::Point::from_bytes(&bytes).map(ValueCommitment)
    }
}
