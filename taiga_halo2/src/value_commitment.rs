use crate::application::Application;
use crate::constant::{NOTE_COMMITMENT_R_GENERATOR, POSEIDON_TO_CURVE_INPUT_LEN};
use crate::note::Note;
use crate::utils::poseidon_to_curve;
use group::{cofactor::CofactorCurveAffine, Curve, Group};
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::pallas;

#[derive(Copy, Clone, Debug)]
pub struct ValueCommitment(pallas::Point);

impl ValueCommitment {
    pub fn new(input_note: &Note, output_note: &Note, blind_r: &pallas::Scalar) -> Self {
        let base_input = derive_value_base(input_note.is_merkle_checked, &input_note.application);
        let base_output =
            derive_value_base(output_note.is_merkle_checked, &output_note.application);
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
}

pub fn derive_value_base(is_merkle_checked: bool, application: &Application) -> pallas::Point {
    let inputs = [
        pallas::Base::from(is_merkle_checked),
        application.get_vp(),
        application.get_vp_data(),
    ];
    poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&inputs)
}
