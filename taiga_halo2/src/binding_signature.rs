use crate::constant::NOTE_COMMITMENT_R_GENERATOR;
use borsh::{BorshDeserialize, BorshSerialize};
use pasta_curves::group::cofactor::CofactorCurveAffine;
use pasta_curves::group::{ff::PrimeField, GroupEncoding};
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use reddsa::{private, Error, SigType, Signature, SigningKey, VerificationKey};
use std::io;

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

impl BindingSignature {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.into()
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let sig = Signature::<TaigaBinding>::from(bytes);
        Self(sig)
    }
}

impl BorshSerialize for BindingSignature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}

impl BorshDeserialize for BindingSignature {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut sig_bytes = [0u8; 64];
        reader.read_exact(&mut sig_bytes)?;
        Ok(Self::from_bytes(sig_bytes))
    }
}

impl BindingSigningKey {
    pub fn sign<R: RngCore + CryptoRng>(&self, rng: R, msg: &[u8]) -> BindingSignature {
        BindingSignature(self.0.sign(rng, msg))
    }

    pub fn get_vk(&self) -> BindingVerificationKey {
        BindingVerificationKey(VerificationKey::from(&self.0))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.into()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::<TaigaBinding>::try_from(bytes)?;
        Ok(Self(key))
    }
}

impl BorshSerialize for BindingSigningKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}

impl BorshDeserialize for BindingSigningKey {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut key_bytes = [0u8; 32];
        reader.read_exact(&mut key_bytes)?;
        Self::from_bytes(key_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "BindingSigningKey not in field")
        })
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
