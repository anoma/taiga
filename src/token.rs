use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::poseidon::{FieldHasher, WIDTH_5};
use crate::utils::bits_to_fields;
use crate::validity_predicate::MockHashVP;
use ark_ff::UniformRand;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use rand::RngCore;

#[derive(Copy, Debug, Clone)]
pub struct TokenAddress<CP: CircuitParameters> {
    pub rcm: CP::CurveScalarField,
    pub token_vp: MockHashVP<CP>,
}

impl<CP: CircuitParameters> TokenAddress<CP> {
    pub fn new(rng: &mut impl RngCore) -> Self {
        let rcm = CP::CurveScalarField::rand(rng);
        Self {
            rcm,
            // TODO: fix this in future.
            token_vp: MockHashVP::dummy(rng),
        }
    }

    pub fn opaque_native(&self) -> Result<CP::CurveScalarField, TaigaError> {
        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_5>();
        let mut token_fields = bits_to_fields::<CP::CurveScalarField>(&self.token_vp.to_bits());
        token_fields.push(self.rcm);
        poseidon_param.native_hash(&token_fields)
    }
}
