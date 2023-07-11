use crate::{
    error::TransactionError, executable::Executable, nullifier::Nullifier,
    value_commitment::ValueCommitment,
};
use borsh::{BorshDeserialize, BorshSerialize};
use pasta_curves::pallas;

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
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

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct InputResource {
    pub resource_logic: ResourceLogic,
    pub prefix: ContentHash,
    pub suffix: Vec<ContentHash>,
    pub resource_data_static: ResourceDataStatic,
    pub resource_data_dynamic: ResourceDataDynamic,
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct OutputResource {
    pub resource_logic: ResourceLogic,
    pub resource_data_static: ResourceDataStatic,
    pub resource_data_dynamic: ResourceDataDynamic,
}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct ResourceLogic {}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct ContentHash {}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct ResourceDataStatic {}

#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct ResourceDataDynamic {}
