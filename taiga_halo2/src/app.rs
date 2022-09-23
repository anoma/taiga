use crate::vp_description::ValidityPredicateDescription;
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct App {
    pub app_vp: ValidityPredicateDescription,
}

impl App {
    pub fn new(app_vp_description: ValidityPredicateDescription) -> Self {
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

impl Default for App {
    fn default() -> App {
        let app_vp = ValidityPredicateDescription::Compressed(pallas::Base::one());
        App { app_vp }
    }
}
