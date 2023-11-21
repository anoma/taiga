use core::fmt;
use halo2_proofs::plonk::Error as PlonkError;
use std::fmt::Display;

#[derive(Debug)]
pub enum TransactionError {
    /// An error occurred when creating halo2 proof.
    Proof(PlonkError),
    /// Binding signature is not valid.
    InvalidBindingSignature,
    /// Binding signature is missing.
    MissingBindingSignatures,
    /// Nullifier is not consistent between the action and the vp.
    InconsistentNullifier,
    /// Output resource commitment is not consistent between the action and the vp.
    InconsistentOutputResourceCommitment,
    /// Owned resource id is not consistent between the action and the vp.
    InconsistentOwneResourceID,
    /// IO error
    IoError(std::io::Error),
    /// Transparent resource nullifier key is missing
    MissingTransparentResourceNullifierKey,
    /// Transparent resource merkle path is missing
    MissingTransparentResourceMerklePath,
    /// Shielded partial Tx binding signature r is missing
    MissingPartialTxBindingSignatureR,
    /// ValidityPredicateRepresentation is not valid
    InvalidValidityPredicateRepresentation,
}

impl Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TransactionError::*;
        match self {
            Proof(e) => f.write_str(&format!("Proof error: {e}")),
            InvalidBindingSignature => f.write_str("Binding signature was invalid"),
            MissingBindingSignatures => f.write_str("Binding signature is missing"),
            InconsistentNullifier => {
                f.write_str("Nullifier is not consistent between the action and the vp")
            }
            InconsistentOutputResourceCommitment => f.write_str(
                "Output resource commitment is not consistent between the action and the vp",
            ),
            InconsistentOwneResourceID => {
                f.write_str("Owned resource id is not consistent between the action and the vp")
            }
            IoError(e) => f.write_str(&format!("IoError error: {e}")),
            MissingTransparentResourceNullifierKey => {
                f.write_str("Transparent resource nullifier key is missing")
            }
            MissingTransparentResourceMerklePath => {
                f.write_str("Transparent resource merkle path is missing")
            }
            MissingPartialTxBindingSignatureR => {
                f.write_str("Shielded partial Tx binding signature r is missing")
            }
            InvalidValidityPredicateRepresentation => {
                f.write_str("ValidityPredicateRepresentation is not valid, add borsh feature if using native vp examples ")
            }
        }
    }
}

impl From<PlonkError> for TransactionError {
    fn from(e: PlonkError) -> Self {
        TransactionError::Proof(e)
    }
}

impl From<std::io::Error> for TransactionError {
    fn from(e: std::io::Error) -> Self {
        TransactionError::IoError(e)
    }
}
