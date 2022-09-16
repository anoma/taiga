use crate::{
    utils::{poseidon_hash, prf_nf},
    vp_description::ValidityPredicateDescription,
};
use ff::Field;
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Copy, Debug, Clone)]
pub struct NullifierDerivingKey(pallas::Base);

impl NullifierDerivingKey {
    pub fn new(nk: pallas::Base) -> Self {
        Self(nk)
    }

    pub fn rand(rng: &mut impl RngCore) -> Self {
        Self(pallas::Base::random(rng))
    }

    pub fn prf_nf(&self, rho: pallas::Base) -> pallas::Base {
        prf_nf(self.0, rho)
    }

    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

impl Default for NullifierDerivingKey {
    fn default() -> NullifierDerivingKey {
        NullifierDerivingKey(pallas::Base::one())
    }
}

/// The user address binded with send vp and received vp.
#[derive(Debug, Clone)]
pub struct User {
    pub send_com: UserSendAddress,
    pub recv_vp: ValidityPredicateDescription,
}

#[derive(Debug, Clone)]
pub enum UserSendAddress {
    Closed(pallas::Base),
    Open(NullifierDerivingKey, ValidityPredicateDescription),
}

impl User {
    pub fn new(
        send_vp: ValidityPredicateDescription,
        recv_vp: ValidityPredicateDescription,
        nk: NullifierDerivingKey,
    ) -> Self {
        let send_com = UserSendAddress::from_open(nk, send_vp);
        Self { send_com, recv_vp }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let nk = NullifierDerivingKey::rand(rng);
        let send_vp = ValidityPredicateDescription::dummy(rng);
        let send_com = UserSendAddress::from_open(nk, send_vp);
        Self {
            send_com,
            recv_vp: ValidityPredicateDescription::dummy(rng),
        }
    }

    pub fn address(&self) -> pallas::Base {
        // address = Com_r(send_com || recv_vp_hash), use poseidon hash as Com_r
        poseidon_hash(self.send_com.get_closed(), self.recv_vp.get_compressed())
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
        self.send_com.get_nk()
    }
}

impl UserSendAddress {
    /// Creates an open user send address.
    pub fn from_open(nk: NullifierDerivingKey, send_vp: ValidityPredicateDescription) -> Self {
        UserSendAddress::Open(nk, send_vp)
    }

    /// Creates a closed user send address.
    pub fn from_closed(x: pallas::Base) -> Self {
        UserSendAddress::Closed(x)
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
        match self {
            UserSendAddress::Closed(_) => None,
            UserSendAddress::Open(nk, _) => Some(*nk),
        }
    }

    pub fn get_send_vp(&self) -> Option<&ValidityPredicateDescription> {
        match self {
            UserSendAddress::Closed(_) => None,
            UserSendAddress::Open(_, send_vp) => Some(send_vp),
        }
    }

    pub fn get_closed(&self) -> pallas::Base {
        match self {
            UserSendAddress::Closed(v) => *v,
            UserSendAddress::Open(nk, send_vp) => {
                // Com_r(send_vp, nk), use poseidon hash as Com_r.
                poseidon_hash(send_vp.get_compressed(), nk.inner())
            }
        }
    }
}

impl Default for User {
    fn default() -> User {
        let nk = NullifierDerivingKey::default();
        let send_vp = ValidityPredicateDescription::Compressed(pallas::Base::one());
        let send_com = UserSendAddress::from_open(nk, send_vp);
        let recv_vp = ValidityPredicateDescription::Compressed(pallas::Base::one());
        User { send_com, recv_vp }
    }
}
