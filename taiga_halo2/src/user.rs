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

    pub fn compute_nf(&self, rho: pallas::Base) -> pallas::Base {
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
    send_data: UserSendData,
    recv_data: UserData,
}

#[derive(Debug, Clone)]
pub enum UserSendData {
    Closed(pallas::Base),
    Open(NullifierDerivingKey, UserData),
}

#[derive(Debug, Clone)]
pub enum UserData {
    General(pallas::Base),
    Vp(ValidityPredicateDescription),
}

impl UserData {
    pub fn from_vp(vp: ValidityPredicateDescription) -> Self {
        UserData::Vp(vp)
    }

    pub fn get_data(&self) -> pallas::Base {
        match self {
            UserData::General(v) => *v,
            UserData::Vp(vp) => vp.get_compressed(),
        }
    }
}

impl User {
    pub fn new(nk: NullifierDerivingKey, send_data: UserData, recv_data: UserData) -> Self {
        let send_data = UserSendData::from_open(nk, send_data);
        Self {
            send_data,
            recv_data,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let nk = NullifierDerivingKey::rand(rng);
        let send_data = UserData::from_vp(ValidityPredicateDescription::dummy(rng));
        let send_data = UserSendData::from_open(nk, send_data);
        Self {
            send_data,
            recv_data: UserData::from_vp(ValidityPredicateDescription::dummy(rng)),
        }
    }

    pub fn address(&self) -> pallas::Base {
        // address = Com_r(send_com || recv_data_hash), use poseidon hash as Com_r
        poseidon_hash(self.send_data.get_closed(), self.recv_data.get_data())
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
        self.send_data.get_nk()
    }

    pub fn get_send_closed(&self) -> pallas::Base {
        self.send_data.get_closed()
    }

    pub fn get_send_data(&self) -> Option<pallas::Base> {
        self.send_data.get_data()
    }

    pub fn get_recv_data(&self) -> pallas::Base {
        self.recv_data.get_data()
    }
}

impl UserSendData {
    /// Creates an open user send address.
    pub fn from_open(nk: NullifierDerivingKey, send_data: UserData) -> Self {
        UserSendData::Open(nk, send_data)
    }

    /// Creates a closed user send address.
    pub fn from_closed(x: pallas::Base) -> Self {
        UserSendData::Closed(x)
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey> {
        match self {
            UserSendData::Closed(_) => None,
            UserSendData::Open(nk, _) => Some(*nk),
        }
    }

    pub fn get_send_vp(&self) -> Option<&ValidityPredicateDescription> {
        match self {
            UserSendData::Open(_, UserData::Vp(vp)) => Some(vp),
            _ => None,
        }
    }

    pub fn get_data(&self) -> Option<pallas::Base> {
        match self {
            UserSendData::Closed(_) => None,
            UserSendData::Open(_, send_data) => Some(send_data.get_data()),
        }
    }

    pub fn get_closed(&self) -> pallas::Base {
        match self {
            UserSendData::Closed(v) => *v,
            UserSendData::Open(nk, send_data) => {
                // Com_r(send_data, nk), use poseidon hash as Com_r.
                poseidon_hash(send_data.get_data(), nk.inner())
            }
        }
    }
}

impl Default for UserData {
    fn default() -> UserData {
        UserData::General(pallas::Base::one())
    }
}

impl Default for User {
    fn default() -> User {
        let nk = NullifierDerivingKey::default();
        let send_data = UserSendData::from_open(nk, UserData::default());
        let recv_data = UserData::default();
        User {
            send_data,
            recv_data,
        }
    }
}
