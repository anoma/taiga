use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::poseidon::{FieldHasher, WIDTH_3};
use crate::utils::bits_to_fields;
use crate::vp_description::ValidityPredicateDescription;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct App<CP: CircuitParameters> {
    pub app_vp: ValidityPredicateDescription<CP>,
}

impl<CP: CircuitParameters> App<CP> {
    pub fn new(app_vp_description: ValidityPredicateDescription<CP>) -> Self {
        Self {
            app_vp: app_vp_description,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        Self {
            // TODO: fix this in future.
            app_vp: ValidityPredicateDescription::dummy(rng),
        }
    }

    pub fn address(&self) -> Result<CP::CurveScalarField, TaigaError> {
        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_3>();

        let address_fields = bits_to_fields::<CP::CurveScalarField>(&self.app_vp.to_bits());
        poseidon_param.native_hash_two(&address_fields[0], &address_fields[1])
    }
}

#[test]
fn app_address_computation() {
    let mut rng = ark_std::test_rng();
    let xan = App::<crate::circuit::circuit_parameters::PairingCircuitParameters>::dummy(&mut rng);
    xan.address().unwrap();
}
