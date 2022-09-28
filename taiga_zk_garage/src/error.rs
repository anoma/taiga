use plonk_core::error::Error;
use plonk_hashing::poseidon::PoseidonError;
use thiserror::Error;

/// Represents errors.
#[derive(Error, Debug)]
pub enum TaigaError {
    /// Occurs when poseidon hash operation failed.
    #[error("Hash error")]
    PoseidonHashError(PoseidonError),

    /// Occurs when plonk operation failed.
    #[error("Plonk error")]
    PlonkError(Error),
}

impl From<PoseidonError> for TaigaError {
    fn from(e: PoseidonError) -> TaigaError {
        TaigaError::PoseidonHashError(e)
    }
}

impl From<Error> for TaigaError {
    fn from(e: Error) -> TaigaError {
        TaigaError::PlonkError(e)
    }
}
