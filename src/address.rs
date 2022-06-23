use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::poseidon::{FieldHasher, WIDTH_5};
use crate::utils::bits_to_fields;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use blake2b_simd::Params;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use rand::RngCore;

const PRF_NK_PERSONALIZATION: &[u8; 12] = b"Taiga_PRF_NK";

/// The nullifier key for note spending.
#[derive(Copy, Debug, Clone)]
pub struct NullifierDerivingKey<F: PrimeField>(F);

/// The payment address binded with send vp and received vp.
#[derive(Copy, Debug, Clone)]
pub struct Address<CP: CircuitParameters> {
    pub nk: NullifierDerivingKey<CP::CurveScalarField>,
    pub rcm: CP::CurveScalarField,
    pub send_vp: MockHashVP<CP>,
    pub recv_vp: MockHashVP<CP>,
}

// TODO: hash_vp = com_q(desc_vp), get it from vpblind circuit in future.
// It seems that we only need com_q(desc_vp) integrity constraint in vpblind circuit,
// and we can use hash_vp as private input in action circuit and vp circuit?
#[derive(Copy, Debug, Clone)]
pub struct MockHashVP<CP: CircuitParameters> {
    hash_vp: CP::CurveBaseField,
}

impl<F: PrimeField> NullifierDerivingKey<F> {
    pub fn rand(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self::prf_nk(&bytes)
    }

    pub fn new_from(rng_bytes: &[u8; 32]) -> Self {
        Self::prf_nk(rng_bytes)
    }

    fn prf_nk(r: &[u8]) -> Self {
        let mut h = Params::new()
            .hash_length(64)
            .personal(PRF_NK_PERSONALIZATION)
            .to_state();
        h.update(r);
        Self::from_bytes(h.finalize().as_bytes())
    }

    pub fn inner(&self) -> F {
        self.0
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(F::from_le_bytes_mod_order(bytes))
    }
}

impl<CP: CircuitParameters> Address<CP> {
    pub fn new(rng: &mut impl RngCore) -> Self {
        let nk = NullifierDerivingKey::<CP::CurveScalarField>::rand(rng);
        let rcm = CP::CurveScalarField::rand(rng);
        Self {
            nk,
            rcm,
            // TODO: fix this in future.
            send_vp: MockHashVP::dummy(rng),
            recv_vp: MockHashVP::dummy(rng),
        }
    }

    pub fn opaque_native(&self) -> Result<CP::CurveScalarField, TaigaError> {
        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_5>();

        // send_part = Com_r( Com_q(desc_vp_addr_send) || nk )
        let mut send_fields = bits_to_fields::<CP::CurveScalarField>(&self.send_vp.to_bits());
        send_fields.push(self.nk.inner());
        let send_hash = poseidon_param.native_hash(&send_fields)?;

        // address = Com_r(send_fields || recv_fields, rcm)
        // TODO: if the Com_r constructed from hash doesn't have the hiding property,
        // we can use PedersenCom(crh(send_fields || recv_fields), rcm) instead?
        let mut address_fields = vec![send_hash];
        let recv_fields = bits_to_fields::<CP::CurveScalarField>(&self.recv_vp.to_bits());
        address_fields.extend(recv_fields);
        address_fields.push(self.rcm);
        poseidon_param.native_hash(&address_fields)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![];
        buf.extend(&self.nk.to_bytes());
        buf.extend(&self.rcm.into_repr().to_bytes_le());
        buf.extend(&self.send_vp.to_bytes());
        buf.extend(&self.recv_vp.to_bytes());

        buf
    }
}

impl<CP: CircuitParameters> MockHashVP<CP> {
    pub fn dummy(rng: &mut impl RngCore) -> Self {
        Self {
            hash_vp: CP::CurveBaseField::rand(rng),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.hash_vp.into_repr().to_bytes_le()
    }

    pub fn to_bits(&self) -> Vec<bool> {
        self.hash_vp.into_repr().to_bits_le()
    }
}
