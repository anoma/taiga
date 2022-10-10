use crate::{vp_description::ValidityPredicateDescription, circuit::circuit_parameters::CircuitParameters};
use pasta_curves::pallas;
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
            app_vp: ValidityPredicateDescription::dummy(rng),
        }
    }

    pub fn address(&self) -> pallas::Base {
        self.app_vp.get_compressed()
    }
}

impl<CP: CircuitParameters> Default for App<CP> {
    fn default() -> App<CP> {
        let app_vp = ValidityPredicateDescription::Compressed(pallas::Base::one());
        App { app_vp }
    }
}
