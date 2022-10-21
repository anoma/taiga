use crate::vp_description::ValidityPredicateDescription;
use ff::Field;
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct App {
    pub vp: ValidityPredicateDescription,
    pub data: pallas::Base,
}

impl App {
    pub fn new(vp: ValidityPredicateDescription, data: pallas::Base) -> Self {
        Self { vp, data }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        Self {
            vp: ValidityPredicateDescription::dummy(rng),
            data: pallas::Base::random(rng),
        }
    }

    pub fn get_vp(&self) -> pallas::Base {
        self.vp.get_compressed()
    }
}

impl Default for App {
    fn default() -> App {
        let vp = ValidityPredicateDescription::Compressed(pallas::Base::one());
        let data = pallas::Base::one();
        App { vp, data }
    }
}
