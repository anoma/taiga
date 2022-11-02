use halo2_proofs::plonk::{self, Circuit};
use pasta_curves::{pallas, vesta};

#[derive(Debug)]
pub struct VerifyingKey {
    pub(crate) params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub(crate) vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn build<C: Circuit<pallas::Base>>(circuit: &C, k: u32) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(k);

        let vk = plonk::keygen_vk(&params, circuit).unwrap();

        VerifyingKey { params, vk }
    }
}

#[derive(Debug)]
pub struct ProvingKey {
    pub params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build<C: Circuit<pallas::Base>>(circuit: &C, k: u32) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(k);

        let vk = plonk::keygen_vk(&params, circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, circuit).unwrap();

        ProvingKey { params, pk }
    }
}
