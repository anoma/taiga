use crate::halo2::utils::prf_nf;
use pasta_curves::pallas;

#[derive(Copy, Debug, Clone)]
pub struct NullifierDerivingKey(pallas::Base);

impl NullifierDerivingKey {
    pub fn prf_nf(&self, rho: pallas::Base) -> pallas::Base {
        prf_nf(self.0, rho)
    }
}
