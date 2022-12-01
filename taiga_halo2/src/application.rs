// use crate::user::{NullifierDerivingKey, User};
use crate::vp_description::ValidityPredicateDescription;
use ff::Field;
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Debug, Clone, Default)]
pub struct Application {
    vp: ValidityPredicateDescription,
    vp_data: pallas::Base,
    // user: User,
}

impl Application {
    pub fn new(
        vp: ValidityPredicateDescription,
        vp_data: pallas::Base,
        // user: User
    ) -> Self {
        Self {
            vp,
            vp_data,
            //  user
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        Self {
            vp: ValidityPredicateDescription::dummy(&mut rng),
            vp_data: pallas::Base::random(&mut rng),
            // user: User::dummy(&mut rng),
        }
    }

    pub fn get_vp(&self) -> pallas::Base {
        self.vp.get_compressed()
    }

    pub fn get_vp_data(&self) -> pallas::Base {
        self.vp_data
    }

    // pub fn get_user_send_closed(&self) -> pallas::Base {
    //     self.user.get_send_closed()
    // }

    // pub fn get_user_send_data(&self) -> Option<pallas::Base> {
    //     self.user.get_send_data()
    // }

    // pub fn get_user_recv_data(&self) -> pallas::Base {
    //     self.user.get_recv_data()
    // }

    // pub fn get_user_address(&self) -> pallas::Base {
    //     self.user.address()
    // }

    // pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
    //     self.user.get_nk()
    // }
}
