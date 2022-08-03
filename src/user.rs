use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::poseidon::{FieldHasher, WIDTH_5};
use crate::utils::bits_to_fields;
use crate::vp_description::ValidityPredicateDescription;
use ark_ff::{BigInteger, PrimeField};
use blake2b_simd::Params;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use rand::RngCore;

const PRF_NK_PERSONALIZATION: &[u8; 12] = b"Taiga_PRF_NK";

/// The nullifier key for note spending.
#[derive(Copy, Debug, Clone)]
pub struct NullifierDerivingKey<F: PrimeField>(F);

/// The user address binded with send vp and received vp.
#[derive(Debug, Clone)]
pub struct User<CP: CircuitParameters> {
    pub send_com: UserSendAddress<CP>,
    pub recv_vp: ValidityPredicateDescription<CP>,
}

#[derive(Debug, Clone)]
pub enum UserSendAddress<CP: CircuitParameters> {
    Closed(CP::CurveScalarField),
    Open(
        NullifierDerivingKey<CP::CurveScalarField>,
        ValidityPredicateDescription<CP>,
    ),
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

    fn prf_nk(random: &[u8]) -> Self {
        let mut h = Params::new()
            .hash_length(64)
            .personal(PRF_NK_PERSONALIZATION)
            .to_state();
        h.update(random);
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

impl<CP: CircuitParameters> User<CP> {

    pub fn new(
        send_vp: ValidityPredicateDescription<CP>,
        recv_vp: ValidityPredicateDescription<CP>,
        nk: NullifierDerivingKey<CP::CurveScalarField>
    ) -> Self {
        let send_com = UserSendAddress::<CP>::from_open(nk, send_vp);
        Self {
            send_com,
            recv_vp,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        let nk = NullifierDerivingKey::<CP::CurveScalarField>::rand(rng);
        let send_vp = ValidityPredicateDescription::dummy(rng);
        let send_com = UserSendAddress::<CP>::from_open(nk, send_vp);
        Self {
            send_com,
            // TODO: fix this in future.
            recv_vp: ValidityPredicateDescription::dummy(rng),
        }
    }

    pub fn address(&self) -> Result<CP::CurveScalarField, TaigaError> {
        // send_com = Com_r( Com_q(send_vp_hash) || nk )
        let send_com = self.send_com.get_closed()?;

        // address = Com_r(send_com || recv_vp_hash)

        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_5>();
        let mut address_fields = vec![send_com];
        let recv_fields = bits_to_fields::<CP::CurveScalarField>(&self.recv_vp.to_bits());
        address_fields.extend(recv_fields);
        poseidon_param.native_hash(&address_fields)
    }
}

impl<CP: CircuitParameters> UserSendAddress<CP> {
    /// Creates an open user send address.
    pub fn from_open(
        nk: NullifierDerivingKey<CP::CurveScalarField>,
        send_vp: ValidityPredicateDescription<CP>,
    ) -> Self {
        UserSendAddress::Open(nk, send_vp)
    }

    /// Creates a closed user send address.
    pub fn from_closed(x: CP::CurveScalarField) -> Self {
        UserSendAddress::Closed(x)
    }

    pub fn get_nk(&self) -> Option<NullifierDerivingKey<CP::CurveScalarField>> {
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

    pub fn get_closed(&self) -> Result<CP::CurveScalarField, TaigaError> {
        match self {
            UserSendAddress::Closed(v) => Ok(*v),
            UserSendAddress::Open(nk, send_vp) => {
                // Init poseidon param.
                let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
                    PoseidonConstants::generate::<WIDTH_5>();

                // send_part = Com_r( Com_q(desc_vp_addr_send) || nk )
                let mut send_fields = bits_to_fields::<CP::CurveScalarField>(&send_vp.to_bits());
                send_fields.push(nk.inner());
                poseidon_param.native_hash(&send_fields)
            }
        }
    }
}

#[test]
fn test_user_address_computation() {
    let mut rng = ark_std::test_rng();
    let u = User::<crate::circuit::circuit_parameters::PairingCircuitParameters>::dummy(&mut rng);
    u.address().unwrap();
}
