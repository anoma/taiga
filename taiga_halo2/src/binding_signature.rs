use crate::constant::NOTE_COMMITMENT_R_GENERATOR;
use pasta_curves::group::{ff::PrimeField, GroupEncoding};
use pasta_curves::group::cofactor::CofactorCurveAffine;
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use reddsa::{private, Error, SigType, Signature, SigningKey, VerificationKey};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TaigaBinding {}

impl Default for TaigaBinding {
    fn default() -> Self {
        unimplemented!()
    }
}

impl private::Sealed<TaigaBinding> for TaigaBinding {
    const H_STAR_PERSONALIZATION: &'static [u8; 16] = b"Taiga_RedPallasH";
    type Point = pallas::Point;
    type Scalar = pallas::Scalar;

    fn basepoint() -> pallas::Point {
        NOTE_COMMITMENT_R_GENERATOR.to_curve()
    }
}

impl SigType for TaigaBinding {}

#[derive(Clone, Debug)]
pub struct BindingSignature(Signature<TaigaBinding>);

#[derive(Clone, Debug)]
pub struct BindingSigningKey(SigningKey<TaigaBinding>);

#[derive(Clone, Debug, PartialEq)]
pub struct BindingVerificationKey(VerificationKey<TaigaBinding>);

impl BindingSigningKey {
    pub fn sign<R: RngCore + CryptoRng>(&self, rng: R, msg: &[u8]) -> BindingSignature {
        BindingSignature(self.0.sign(rng, msg))
    }

    pub fn get_vk(&self) -> BindingVerificationKey {
        BindingVerificationKey(VerificationKey::from(&self.0))
    }
}

impl From<pallas::Scalar> for BindingSigningKey {
    fn from(sk: pallas::Scalar) -> Self {
        BindingSigningKey(sk.to_repr().try_into().unwrap())
    }
}

impl BindingVerificationKey {
    pub fn verify(&self, msg: &[u8], signature: &BindingSignature) -> Result<(), Error> {
        self.0.verify(msg, &signature.0)
    }
}

impl From<pallas::Point> for BindingVerificationKey {
    fn from(p: pallas::Point) -> Self {
        BindingVerificationKey(p.to_bytes().try_into().unwrap())
    }
}
