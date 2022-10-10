use crate::{
    circuit::circuit_parameters::CircuitParameters,
    utils::{poseidon_hash, prf_nf},
    vp_description::ValidityPredicateDescription,
};
use ff::Field;
use pasta_curves::pallas;
use rand::RngCore;

#[derive(Copy, Debug, Clone)]
pub struct NullifierDerivingKey<CP: CircuitParameters>(CP::CurveScalarField);

impl<CP: CircuitParameters> NullifierDerivingKey<CP> {
    pub fn new(nk: CP::CurveScalarField) -> Self {
        Self(nk)
    }

    pub fn rand(rng: &mut impl RngCore) -> Self {
        Self(CP::CurveScalarField::random(rng))
    }

    pub fn compute_nf(&self, rho: CP::CurveScalarField) -> CP::CurveScalarField {
        prf_nf::<CP>(self.0, rho)
    }

    pub fn inner(&self) -> CP::CurveScalarField {
        self.0
    }
}

impl<CP: CircuitParameters> Default for NullifierDerivingKey<CP> {
    fn default() -> NullifierDerivingKey<CP> {
        NullifierDerivingKey(CP::CurveScalarField::one())
    }
}

/// The user address binded with send vp and received vp.
#[derive(Debug, Clone)]
pub struct User<CP: CircuitParameters> {
    pub send_com: UserSendAddress<CP>,
    pub recv_vp: ValidityPredicateDescription<CP>,
}

#[derive(Debug, Clone)]
pub enum UserSendAddress<CP: CircuitParameters> {
    Closed(CP::CurveScalarField),
    Open(NullifierDerivingKey<CP>, ValidityPredicateDescription<CP>),
}

impl<CP: CircuitParameters> User<CP> {
    pub fn new(
        send_vp: ValidityPredicateDescription<CP>,
        recv_vp: ValidityPredicateDescription<CP>,
        nk: NullifierDerivingKey<CP>,
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

    pub fn address(&self) -> CP::CurveScalarField {
        // address = Com_r(send_com || recv_vp_hash), use poseidon hash as Com_r
        poseidon_hash::<CP>(self.send_com.get_closed(), self.recv_vp.get_compressed())
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey<CP>> {
        self.send_com.get_nk()
    }
}

impl<CP: CircuitParameters> UserSendAddress<CP> {
    /// Creates an open user send address.
    pub fn from_open(nk: NullifierDerivingKey<CP>, send_vp: ValidityPredicateDescription<CP>) -> Self {
        UserSendAddress::Open(nk, send_vp)
    }

    /// Creates a closed user send address.
    pub fn from_closed(x: CP::CurveScalarField) -> Self {
        UserSendAddress::Closed(x)
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey<CP>> {
        match self {
            UserSendAddress::Closed(_) => None,
            UserSendAddress::Open(nk, _) => Some(*nk),
        }
    }

    pub fn get_send_vp(&self) -> Option<&ValidityPredicateDescription<CP>> {
        match self {
            UserSendAddress::Closed(_) => None,
            UserSendAddress::Open(_, send_vp) => Some(send_vp),
        }
    }

    pub fn get_closed(&self) -> CP::CurveScalarField {
        match self {
            UserSendAddress::Closed(v) => *v,
            UserSendAddress::Open(nk, send_vp) => {
                // Com_r(send_vp, nk), use poseidon hash as Com_r.
                poseidon_hash::<CP>(send_vp.get_compressed(), nk.inner())
            }
        }
    }
}

impl<CP: CircuitParameters> Default for User<CP> {
    fn default() -> User<CP> {
        let nk = NullifierDerivingKey::default();
        let send_vp = ValidityPredicateDescription::Compressed(CP::CurveScalarField::one());
        let send_com = UserSendAddress::from_open(nk, send_vp);
        let recv_vp = ValidityPredicateDescription::Compressed(CP::CurveScalarField::one());
        User { send_com, recv_vp }
    }
}
