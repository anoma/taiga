use crate::error::TransactionError;
use crate::shielded_ptx::{ShieldedPartialTxBundle, ShieldedResult};
use crate::transparent_ptx::{TransparentPartialTxBundle, TransparentResult};

#[derive(Debug, Clone)]
pub struct Transaction {
    // TODO: Other parameters to be added.
    shielded_ptx_bundle: Option<ShieldedPartialTxBundle>,
    transparent_ptx_bundle: Option<TransparentPartialTxBundle>,
}

impl Transaction {
    pub fn new(
        shielded_ptx_bundle: Option<ShieldedPartialTxBundle>,
        transparent_ptx_bundle: Option<TransparentPartialTxBundle>,
    ) -> Self {
        Self {
            shielded_ptx_bundle,
            transparent_ptx_bundle,
        }
    }

    pub fn transparent_bundle(&self) -> Option<&TransparentPartialTxBundle> {
        self.transparent_ptx_bundle.as_ref()
    }

    pub fn shielded_bundle(&self) -> Option<&ShieldedPartialTxBundle> {
        self.shielded_ptx_bundle.as_ref()
    }

    #[allow(clippy::type_complexity)]
    pub fn execute(
        &self,
    ) -> Result<(Option<ShieldedResult>, Option<TransparentResult>), TransactionError> {
        let shielded_result = match self.shielded_bundle() {
            Some(bundle) => Some(bundle.execute()?),
            None => None,
        };

        let transparent_result = match self.transparent_bundle() {
            Some(bundle) => Some(bundle.execute()?),
            None => None,
        };

        // TODO: if the shielded and transparent mixing is allowed, check the balance.

        Ok((shielded_result, transparent_result))
    }
}
