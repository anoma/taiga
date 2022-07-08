use crate::circuit::circuit_parameters::CircuitParameters;
use crate::utils::bits_to_fields;
use crate::validity_predicate::MockHashVP;
use rand::RngCore;

#[derive(Copy, Debug, Clone)]
pub struct Token<CP: CircuitParameters> {
    pub token_vp: MockHashVP<CP>,
}

impl<CP: CircuitParameters> Token<CP> {
    pub fn new(rng: &mut impl RngCore) -> Self {
        Self {
            // TODO: fix this in future.
            token_vp: MockHashVP::dummy(rng),
        }
    }

    pub fn address(&self) -> Vec<CP::CurveScalarField> {
        bits_to_fields::<CP::CurveScalarField>(&self.token_vp.to_bits())
    }
}
