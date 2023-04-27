use crate::error::TransactionError;
use crate::value_commitment::ValueCommitment;

#[derive(Debug, Clone)]
pub struct TransparentPartialTxBundle {
    partial_txs: Vec<TransparentPartialTransaction>,
    authorization: Authorization,
}

#[derive(Debug, Clone)]
pub struct TransparentResult {
    pub nullifiers: Vec<TransparentNullifier>,
    pub outputs: Vec<OutputResource>,
}

#[derive(Debug, Clone)]
pub struct TransparentNullifier {}

#[derive(Debug, Clone)]
pub struct Authorization {}

#[derive(Debug, Clone)]
pub struct TransparentPartialTransaction {
    pub inputs: Vec<InputResource>,
    pub outputs: Vec<OutputResource>,
}

impl TransparentPartialTxBundle {
    pub fn execute(&self) -> Result<TransparentResult, TransactionError> {
        // TODO: figure out how transparent ptx executes
        Ok(TransparentResult {
            nullifiers: vec![],
            outputs: vec![],
        })
    }

    pub fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        unimplemented!()
    }

    pub fn digest(&self) -> [u8; 32] {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct InputResource {
    pub resource_logic: ResourceLogic,
    pub prefix: ContentHash,
    pub suffix: Vec<ContentHash>,
    pub resource_data_static: ResourceDataStatic,
    pub resource_data_dynamic: ResourceDataDynamic,
}

#[derive(Debug, Clone)]
pub struct OutputResource {
    pub resource_logic: ResourceLogic,
    pub resource_data_static: ResourceDataStatic,
    pub resource_data_dynamic: ResourceDataDynamic,
}

#[derive(Debug, Clone)]
pub struct ResourceLogic {}

#[derive(Debug, Clone)]
pub struct ContentHash {}

#[derive(Debug, Clone)]
pub struct ResourceDataStatic {}

#[derive(Debug, Clone)]
pub struct ResourceDataDynamic {}
