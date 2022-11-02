use crate::keys::{ProvingKey, VerifyingKey};

use halo2_proofs::{
    plonk::{self, Circuit, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};
use rand::RngCore;

extern crate taiga_halo2;

#[derive(Clone)]
pub struct Proof(Vec<u8>);

impl Proof {
    /// Creates a proof for the given circuits and instances.
    pub fn create<C: Circuit<pallas::Base>>(
        pk: &ProvingKey,
        circuit: C,
        instance: &[&[pallas::Base]],
        mut rng: impl RngCore,
    ) -> Result<Self, plonk::Error> {
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &pk.params,
            &pk.pk,
            &[circuit],
            &[instance],
            &mut rng,
            &mut transcript,
        )?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    pub fn verify(
        &self,
        vk: &VerifyingKey,
        instance: &[&[pallas::Base]],
    ) -> Result<(), plonk::Error> {
        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, &[instance], &mut transcript)
    }

    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
}
