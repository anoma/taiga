#[cfg(feature = "borsh")]
use crate::{
    circuit::vp_bytecode::ApplicationByteCode, compliance::ComplianceInfo,
    transaction::TransactionResult,
};
use crate::{
    error::TransactionError,
    nullifier::Nullifier,
    resource::Resource,
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};
use ff::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;

pub const RESOURCE_SIZE: usize = 202;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// Create a resource
/// logic is a hash of a predicate associated with the resource
/// label specifies the fungibility domain for the resource
/// value is the fungible data of the resource
/// nk is the nullifier key
/// nonce guarantees the uniqueness of the resource computable fields
/// is_ephemeral is false for normal resources, true for intent(ephemeral) resources
///
/// In practice, input resources are fetched and decrypted from blockchain storage.
/// The create_input_resource API is only for test.
pub fn create_input_resource(
    logic: pallas::Base,
    label: pallas::Base,
    value: pallas::Base,
    quantity: u64,
    nk: pallas::Base,
    is_ephemeral: bool,
) -> Resource {
    let mut rng = OsRng;
    let nonce = Nullifier::random(&mut rng);
    let rseed = pallas::Base::random(&mut rng);
    Resource::new_input_resource(
        logic,
        label,
        value,
        quantity,
        nk,
        nonce,
        is_ephemeral,
        rseed,
    )
}

///
pub fn create_output_resource(
    logic: pallas::Base,
    label: pallas::Base,
    value: pallas::Base,
    quantity: u64,
    // The owner of output resource has the nullifer key and exposes the nullifier_key commitment to output creator.
    npk: pallas::Base,
    is_ephemeral: bool,
) -> Resource {
    let mut rng = OsRng;
    let rseed = pallas::Base::random(&mut rng);
    Resource::new_output_resource(logic, label, value, quantity, npk, is_ephemeral, rseed)
}

/// Resource borsh serialization
///
/// Resource size: 202 bytes
///
/// Resource layout:
/// |   Parameters          | type          |size(bytes)|
/// |   -                   |   -           |   -       |
/// |   logic               | pallas::Base  |   32      |
/// |   label               | pallas::Base  |   32      |
/// |   value               | pallas::Base  |   32      |
/// |   quantity            | u64           |   8       |
/// |   nk_container type   | u8            |   1       |
/// |   npk                 | pallas::Base  |   32      |
/// |   nonce               | pallas::Base  |   32      |
/// |   is_ephemeral        | u8            |   1       |
/// |   rseed               | pallas::Base  |   32      |
#[cfg(feature = "borsh")]
pub fn resource_serialize(resource: &Resource) -> std::io::Result<Vec<u8>> {
    let mut result = Vec::with_capacity(RESOURCE_SIZE);
    resource.serialize(&mut result)?;
    Ok(result)
}

/// Resource borsh deserialization
#[cfg(feature = "borsh")]
pub fn resource_deserialize(bytes: Vec<u8>) -> std::io::Result<Resource> {
    if bytes.len() != RESOURCE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incorrect resource size",
        ));
    }
    BorshDeserialize::deserialize(&mut bytes.as_ref())
}

/// Shielded Partial Transaction borsh serialization
///
/// Shielded Partial Transaction layout:
/// | Parameters                        | type                  | size(bytes)   |
/// |       -                           |       -               |   -           |
/// | 2 compliance proofs               | ComplianceVerifyingInfo| 4676 * 2      |
/// | input1 static vp proof            | VPVerifyingInfo       | 158216        |
/// | input1 dynamic vp num(by borsh)   | u32                   | 4             |
/// | input1 dynamic vp proof           | VPVerifyingInfo       | 158216 * num  |
/// | input2 static vp proof            | VPVerifyingInfo       | 158216        |
/// | input2 dynamic vp num(by borsh)   | u32                   | 4             |
/// | input2 dynamic vp proof           | VPVerifyingInfo       | 158216 * num  |
/// | output1 static vp proof           | VPVerifyingInfo       | 158216        |
/// | output1 dynamic vp num(by borsh)  | u32                   | 4             |
/// | output1 dynamic vp proofs         | VPVerifyingInfo       | 158216 * num  |
/// | output2 static vp proof           | VPVerifyingInfo       | 158216        |
/// | output2 dynamic vp num(by borsh)  | u32                   | 4             |
/// | output2 dynamic vp proofs         | VPVerifyingInfo       | 158216 * num  |
/// | binding_sig_r                     | Option<pallas::Scalar>| 1 or (1 + 32) |
/// | hints                             | Vec<u8>               | -             |
///
/// Resource: Ultimately, vp proofs won't go to the ptx. It's verifier proofs instead.
/// The verifier proof may have a much smaller size since the verifier verifying-key
/// is a constant and can be cached.
#[cfg(feature = "borsh")]
pub fn partial_transaction_serialize(ptx: &ShieldedPartialTransaction) -> std::io::Result<Vec<u8>> {
    borsh::to_vec(&ptx)
}

/// Shielded Partial Transaction borsh deserialization
#[cfg(feature = "borsh")]
pub fn partial_transaction_deserialize(
    bytes: Vec<u8>,
) -> std::io::Result<ShieldedPartialTransaction> {
    BorshDeserialize::deserialize(&mut bytes.as_ref())
}

/// Transaction borsh serialization
///
/// Transaction layout:
/// | Parameters                                                | type                          | size(bytes)|
/// |                   -                                       |       -                       |   -   |
/// | shielded_ptx_bundle(a list of shielded ptx)               | ShieldedPartialTxBundle       | -     |
/// | TODO: transparent_ptx_bundle(a list of transparent ptx)   | TransparentPartialTxBundle    | -     |
/// | signature                                                 | BindingSignature              | 32    |
///
#[cfg(feature = "borsh")]
pub fn transaction_serialize(tx: &Transaction) -> std::io::Result<Vec<u8>> {
    borsh::to_vec(&tx)
}

/// Transaction borsh deserialization
///
#[cfg(feature = "borsh")]
pub fn transaction_deserialize(bytes: Vec<u8>) -> std::io::Result<Transaction> {
    BorshDeserialize::deserialize(&mut bytes.as_ref())
}

/// Create a shielded partial transaction from vp bytecode
#[cfg(feature = "borsh")]
pub fn create_shielded_partial_transaction(
    compliances: Vec<ComplianceInfo>,
    input_resource_app: Vec<ApplicationByteCode>,
    output_resource_app: Vec<ApplicationByteCode>,
    hints: Vec<u8>,
) -> Result<ShieldedPartialTransaction, TransactionError> {
    let rng = OsRng;
    ShieldedPartialTransaction::from_bytecode(
        compliances,
        input_resource_app,
        output_resource_app,
        hints,
        rng,
    )
}

/// Create a transaction from partial transactions
///
pub fn create_transaction(
    shielded_ptxs: Vec<ShieldedPartialTransaction>,
    // TODO: add transparent_ptxs
    // transparent_ptxs: Vec<TransparentPartialTransaction>,
) -> Result<Transaction, TransactionError> {
    let rng = OsRng;
    let shielded_ptx_bundle = ShieldedPartialTxBundle::new(shielded_ptxs);
    // empty transparent_ptx_bundle
    let transparent_ptx_bundle = TransparentPartialTxBundle::default();
    Transaction::build(rng, shielded_ptx_bundle, transparent_ptx_bundle)
}

/// Verify a transaction and return the results
///
/// TransactionResult layout:
/// | Parameters     | type         | size(bytes)|
/// |       -        |    -         |   -        |
/// | anchor num     | u32          | 4          |
/// | anchors        | pallas::Base | 32 * num   |
/// | nullifier num  | u32          | 4          |
/// | nullifiers     | pallas::Base | 32 * num   |
/// | output cm num  | u32          | 4          |
/// | output cms     | pallas::Base | 32 * num   |
///
#[cfg(feature = "borsh")]
pub fn verify_transaction(tx_bytes: Vec<u8>) -> Result<TransactionResult, TransactionError> {
    // Decode the tx
    let tx = transaction_deserialize(tx_bytes)?;

    // Verify the tx
    tx.execute()
}

/// Verify a shielded transaction
///
#[cfg(feature = "borsh")]
pub fn verify_shielded_partial_transaction(ptx_bytes: Vec<u8>) -> Result<(), TransactionError> {
    // Decode the ptx
    let ptx = partial_transaction_deserialize(ptx_bytes)?;

    // Verify the ptx
    ptx.verify_proof()
}

#[cfg(test)]
#[cfg(feature = "borsh")]
pub mod tests {
    use crate::{
        nullifier::tests::random_nullifier_key_commitment, resource::tests::random_resource,
        taiga_api::*,
    };
    use rand::rngs::OsRng;

    #[test]
    fn resource_borsh_serialization_api_test() {
        let mut rng = OsRng;
        let input_resource = random_resource(&mut rng);
        {
            let bytes = resource_serialize(&input_resource).unwrap();
            let de_input_resource = resource_deserialize(bytes).unwrap();
            assert_eq!(input_resource, de_input_resource);
        }

        {
            let mut output_resource = input_resource;
            output_resource.nk_container = random_nullifier_key_commitment(&mut rng);
            let bytes = resource_serialize(&output_resource).unwrap();
            let de_output_resource = resource_deserialize(bytes).unwrap();
            assert_eq!(output_resource, de_output_resource);
        }
    }

    // #[ignore]
    #[test]
    fn ptx_example_test() {
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        use crate::compliance::ComplianceInfo;
        use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
        use crate::merkle_tree::MerklePath;
        use crate::resource::tests::random_resource;

        let mut rng = OsRng;

        // construct resources
        let input_resource_1 = random_resource(&mut rng);
        let input_resource_1_nf = input_resource_1.get_nf().unwrap();
        let mut output_resource_1 = random_resource(&mut rng);
        let merkle_path_1 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let compliance_1 = ComplianceInfo::new(
            input_resource_1,
            merkle_path_1,
            None,
            &mut output_resource_1,
            &mut rng,
        );

        let input_resource_2 = random_resource(&mut rng);
        let input_resource_2_nf = input_resource_2.get_nf().unwrap();
        let mut output_resource_2 = random_resource(&mut rng);
        let merkle_path_2 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let compliance_2 = ComplianceInfo::new(
            input_resource_2,
            merkle_path_2,
            None,
            &mut output_resource_2,
            &mut rng,
        );

        // construct applications
        let input_resource_1_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_resource_1_nf.inner(),
                [input_resource_1, input_resource_2],
                [output_resource_1, output_resource_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let input_resource_2_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_resource_2_nf.inner(),
                [input_resource_1, input_resource_2],
                [output_resource_1, output_resource_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let output_resource_1_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                output_resource_1.commitment().inner(),
                [input_resource_1, input_resource_2],
                [output_resource_1, output_resource_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let output_resource_2_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                output_resource_2.commitment().inner(),
                [input_resource_1, input_resource_2],
                [output_resource_1, output_resource_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        // construct ptx
        let ptx = create_shielded_partial_transaction(
            vec![compliance_1, compliance_2],
            vec![input_resource_1_app, input_resource_2_app],
            vec![output_resource_1_app, output_resource_2_app],
            vec![],
        )
        .unwrap();

        let ptx_bytes = partial_transaction_serialize(&ptx).unwrap();
        verify_shielded_partial_transaction(ptx_bytes).unwrap();
    }
}
