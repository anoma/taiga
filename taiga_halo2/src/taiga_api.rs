#[cfg(feature = "borsh")]
use crate::{
    action::ActionInfo, circuit::vp_bytecode::ApplicationByteCode, transaction::TransactionResult,
};
use crate::{
    error::TransactionError,
    note::{Note, RandomSeed},
    nullifier::{Nullifier, NullifierKeyContainer},
    shielded_ptx::ShieldedPartialTransaction,
    transaction::{ShieldedPartialTxBundle, Transaction, TransparentPartialTxBundle},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;

pub const NOTE_SIZE: usize = 234;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// Create a note
/// app_vk is the compressed verifying key of application(static) VP
/// app_data_static is the encoded data that is defined in application vp
/// app_data_dynamic is the data defined in application vp and will NOT be used to derive type
/// value is the quantity of notes
/// nk is the nullifier key
/// rho is the old nullifier
/// is_merkle_checked is true for normal notes, false for intent(ephemeral) notes
///
/// In practice, input notes are fetched and decrypted from blockchain storage.
/// The create_input_note API is only for test.
pub fn create_input_note(
    app_vk: pallas::Base,
    app_data_static: pallas::Base,
    app_data_dynamic: pallas::Base,
    value: u64,
    nk: pallas::Base,
    is_merkle_checked: bool,
) -> Note {
    let rng = OsRng;
    let nk_container = NullifierKeyContainer::from_key(nk);
    let rho = Nullifier::default();
    let rseed = RandomSeed::random(rng);
    Note::new(
        app_vk,
        app_data_static,
        app_data_dynamic,
        value,
        nk_container,
        rho,
        is_merkle_checked,
        rseed,
    )
}

///
pub fn create_output_note(
    app_vk: pallas::Base,
    app_data_static: pallas::Base,
    app_data_dynamic: pallas::Base,
    value: u64,
    // The owner of output note has the nullifer key and exposes the nullifier_key commitment to output creator.
    nk_com: pallas::Base,
    // TODO: remove the input_nf, and get it at run time.
    input_nf: Nullifier,
    is_merkle_checked: bool,
) -> Note {
    let rng = OsRng;
    let nk_container = NullifierKeyContainer::from_commitment(nk_com);
    let rseed = RandomSeed::random(rng);
    Note::new(
        app_vk,
        app_data_static,
        app_data_dynamic,
        value,
        nk_container,
        input_nf,
        is_merkle_checked,
        rseed,
    )
}

/// Note borsh serialization
///
/// Note size: 234 bytes
///
/// Note layout:
/// |   Parameters          | type          |size(bytes)|
/// |   -                   |   -           |   -       |
/// |   app_vk              | pallas::Base  |   32      |
/// |   app_data_static     | pallas::Base  |   32      |
/// |   app_data_dynamic    | pallas::Base  |   32      |
/// |   value(quantity)     | u64           |   8       |
/// |   nk_container type   | u8            |   1       |
/// |   nk_com/nk           | pallas::Base  |   32      |
/// |   rho                 | pallas::Base  |   32      |
/// |   psi                 | pallas::Base  |   32      |
/// |   rcm                 | pallas::Base  |   32      |
/// |   is_merkle_checked   | u8            |   1       |
#[cfg(feature = "borsh")]
pub fn note_serialize(note: &Note) -> std::io::Result<Vec<u8>> {
    let mut result = Vec::with_capacity(NOTE_SIZE);
    note.serialize(&mut result)?;
    Ok(result)
}

/// Note borsh deserialization
#[cfg(feature = "borsh")]
pub fn note_deserialize(bytes: Vec<u8>) -> std::io::Result<Note> {
    if bytes.len() != NOTE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incorrect note size",
        ));
    }
    BorshDeserialize::deserialize(&mut bytes.as_ref())
}

/// Shielded Partial Transaction borsh serialization
///
/// Shielded Partial Transaction layout:
/// | Parameters                        | type                  | size(bytes)   |
/// |       -                           |       -               |   -           |
/// | 2 action proofs                   | ActionVerifyingInfo   | 4676 * 2      |
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
/// Note: Ultimately, vp proofs won't go to the ptx. It's verifier proofs instead.
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
    actions: Vec<ActionInfo>,
    input_note_app: Vec<ApplicationByteCode>,
    output_note_app: Vec<ApplicationByteCode>,
    hints: Vec<u8>,
) -> ShieldedPartialTransaction {
    let rng = OsRng;
    ShieldedPartialTransaction::from_bytecode(actions, input_note_app, output_note_app, hints, rng)
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
        note::tests::{random_input_note, random_output_note},
        taiga_api::*,
    };
    use rand::rngs::OsRng;

    #[test]
    fn note_borsh_serialization_api_test() {
        let mut rng = OsRng;
        let input_note = random_input_note(&mut rng);
        {
            let bytes = note_serialize(&input_note).unwrap();
            let de_input_note = note_deserialize(bytes).unwrap();
            assert_eq!(input_note, de_input_note);
        }

        {
            let output_note = random_output_note(&mut rng, input_note.rho);
            let bytes = note_serialize(&output_note).unwrap();
            let de_output_note = note_deserialize(bytes).unwrap();
            assert_eq!(output_note, de_output_note);
        }
    }

    #[ignore]
    #[test]
    fn ptx_example_test() {
        use crate::action::ActionInfo;
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
        use crate::merkle_tree::MerklePath;
        use crate::note::{
            tests::{random_input_note, random_output_note},
            RandomSeed,
        };

        let mut rng = OsRng;

        // construct notes
        let input_note_1 = random_input_note(&mut rng);
        let input_note_1_nf = input_note_1.get_nf().unwrap();
        let output_note_1 = random_output_note(&mut rng, input_note_1_nf);
        let merkle_path_1 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let anchor_1 = input_note_1.calculate_root(&merkle_path_1);
        let rseed_1 = RandomSeed::random(&mut rng);
        let action_1 = ActionInfo::new(
            input_note_1,
            merkle_path_1,
            anchor_1,
            output_note_1,
            rseed_1,
        );

        let input_note_2 = random_input_note(&mut rng);
        let input_note_2_nf = input_note_2.get_nf().unwrap();
        let output_note_2 = random_output_note(&mut rng, input_note_2_nf);
        let merkle_path_2 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let anchor_2 = input_note_2.calculate_root(&merkle_path_2);
        let rseed_2 = RandomSeed::random(&mut rng);
        let action_2 = ActionInfo::new(
            input_note_2,
            merkle_path_2,
            anchor_2,
            output_note_2,
            rseed_2,
        );

        // construct applications
        let input_note_1_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_note_1_nf.inner(),
                [input_note_1, input_note_2],
                [output_note_1, output_note_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let input_note_2_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_note_2_nf.inner(),
                [input_note_1, input_note_2],
                [output_note_1, output_note_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let output_note_1_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                output_note_1.commitment().inner(),
                [input_note_1, input_note_2],
                [output_note_1, output_note_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let output_note_2_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                output_note_2.commitment().inner(),
                [input_note_1, input_note_2],
                [output_note_1, output_note_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        // construct ptx
        let ptx = create_shielded_partial_transaction(
            vec![action_1, action_2],
            vec![input_note_1_app, input_note_2_app],
            vec![output_note_1_app, output_note_2_app],
            vec![],
        );

        let ptx_bytes = partial_transaction_serialize(&ptx).unwrap();
        verify_shielded_partial_transaction(ptx_bytes).unwrap();
    }
}
