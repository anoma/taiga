use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::poseidon::{FieldHasher, WIDTH_3};
use crate::utils::bits_to_fields;
use crate::vp_description::ValidityPredicateDescription;
use plonk_hashing::poseidon::constants::PoseidonConstants;
use rand::RngCore;
use pasta_curves::vesta;

#[derive(Debug, Clone)]
pub struct Token{
    pub token_vp: ValidityPredicateDescription,
}

impl Token{
    pub fn new(rng: &mut impl RngCore) -> Self {
        Self {
            // TODO: fix this in future.
            token_vp: ValidityPredicateDescription::dummy(rng),
        }
    }

    pub fn address(&self) -> Result<vesta::Scalar, TaigaError> {
        // Init poseidon param.
        let poseidon_param: PoseidonConstants<vesta::Scalar> =
            PoseidonConstants::generate::<WIDTH_3>();

        let address_fields = bits_to_fields::<vesta::Scalar>(&self.token_vp.to_bits());
        poseidon_param.native_hash_two(&address_fields[0], &address_fields[1])
    }
}

#[test]
fn token_address_computation() {
    let mut rng = ark_std::test_rng();
    let xan = Token::<crate::circuit::circuit_parameters::PairingCircuitParameters>::new(&mut rng);
    xan.address().unwrap();
}
