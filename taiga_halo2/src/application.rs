use crate::vp_description::ValidityPredicateDescription;
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Debug, Clone, Default)]
pub struct Application {
    vp: ValidityPredicateDescription,
}

impl Application {
    pub fn new(vp: ValidityPredicateDescription) -> Self {
        Self { vp }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        Self {
            vp: ValidityPredicateDescription::dummy(&mut rng),
        }
    }

    pub fn get_vp(&self) -> pallas::Base {
        self.vp.get_compressed()
    }
}
