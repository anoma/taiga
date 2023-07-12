use crate::constant::NOTE_COMMITMENT_R_GENERATOR;
use crate::note::Note;
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::group::cofactor::CofactorCurveAffine;
use pasta_curves::group::{Curve, Group, GroupEncoding};
use pasta_curves::pallas;
use subtle::CtOption;

#[derive(Copy, Clone, Debug)]
pub struct ValueCommitment(pallas::Point);

impl ValueCommitment {
    pub fn new(input_note: &Note, output_note: &Note, blind_r: &pallas::Scalar) -> Self {
        let base_input = input_note.get_note_type();
        let base_output = output_note.get_note_type();
        ValueCommitment(
            base_input * pallas::Scalar::from(input_note.value)
                - base_output * pallas::Scalar::from(output_note.value)
                + NOTE_COMMITMENT_R_GENERATOR.to_curve() * blind_r,
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
