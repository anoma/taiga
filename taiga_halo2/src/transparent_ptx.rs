use crate::{
    error::TransactionError, executable::Executable, nullifier::Nullifier,
    value_commitment::ValueCommitment,
};
use pasta_curves::pallas;

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransparentPartialTransaction {
    pub inputs: Vec<InputResource>,
    pub outputs: Vec<OutputResource>,
}

impl Executable for TransparentPartialTransaction {
    fn execute(&self) -> Result<(), TransactionError> {
        // TODO: figure out how transparent ptx executes
        unimplemented!()
    }

    fn get_nullifiers(&self) -> Vec<Nullifier> {
        unimplemented!()
    }

    fn get_output_cms(&self) -> Vec<pallas::Base> {
        unimplemented!()
    }

    fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        unimplemented!()
    }

    fn get_anchors(&self) -> Vec<pallas::Base> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InputResource {
    pub resource_logic: ResourceLogic,
    pub prefix: ContentHash,
    pub suffix: Vec<ContentHash>,
    pub resource_data_static: ResourceDataStatic,
    pub resource_data_dynamic: ResourceDataDynamic,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OutputResource {
    pub resource_logic: ResourceLogic,
    pub resource_data_static: ResourceDataStatic,
    pub resource_data_dynamic: ResourceDataDynamic,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceLogic {}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ContentHash {}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceDataStatic {}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceDataDynamic {}
