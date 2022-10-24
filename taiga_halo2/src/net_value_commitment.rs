use crate::app::App;
use crate::constant::NOTE_COMMITMENT_R_GENERATOR;
use crate::note::Note;
use ff::PrimeField;
use group::{cofactor::CofactorCurveAffine, Curve, Group};
use halo2_proofs::arithmetic::{CurveAffine, CurveExt};
use pasta_curves::pallas;

#[derive(Copy, Clone, Debug)]
pub struct NetValueCommitment(pallas::Point);

impl NetValueCommitment {
    pub fn new(input_note: &Note, output_note: &Note, blind_r: &pallas::Scalar) -> Self {
        let base_input = derivate_value_base(input_note.is_normal, &input_note.app);
        let base_output = derivate_value_base(output_note.is_normal, &output_note.app);
        NetValueCommitment(
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
}

pub fn derivate_value_base(is_normal: bool, app: &App) -> pallas::Point {
    let hash = pallas::Point::hash_to_curve("taiga:test");
    let mut bytes: Vec<u8> = vec![is_normal.into()];
    bytes.extend_from_slice(&app.get_vp().to_repr());
    bytes.extend_from_slice(&app.data.to_repr());
    hash(&bytes)
}
