use crate::{
    error::TransactionError,
    executable::Executable,
    merkle_tree::{Anchor, MerklePath},
    note::{Note, NoteCommitment},
    nullifier::{Nullifier, NullifierKeyContainer},
    value_commitment::ValueCommitment,
};

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use rand::RngCore;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransparentPartialTransaction {
    inputs: Vec<InputResource>,
    outputs: Vec<OutputResource>,
    hints: Vec<u8>,
}

impl TransparentPartialTransaction {
    pub fn new<R: RngCore>(
        inputs: Vec<InputResource>,
        mut outputs: Vec<OutputResource>,
        hints: Vec<u8>,
        mut rng: R,
    ) -> Self {
        outputs
            .iter_mut()
            .zip(inputs.iter())
            .for_each(|(output, input)| output.note.reset_rho(&input.note, &mut rng));
        Self {
            inputs,
            outputs,
            hints,
        }
    }
}

impl Executable for TransparentPartialTransaction {
    fn execute(&self) -> Result<(), TransactionError> {
        assert_eq!(self.inputs.len(), self.outputs.len());
        for input in self.inputs.iter() {
            // check nullifer_key is provided
            if let NullifierKeyContainer::Commitment(_) = input.note.nk_container {
                return Err(TransactionError::MissingTransparentResourceNullifierKey);
            }

            // check merkle_path is provided
            if input.merkle_path.is_none() && input.note.is_merkle_checked {
                return Err(TransactionError::MissingTransparentResourceMerklePath);
            }
        }

        // TODO: figure out how transparent ptx executes
        // VP should be checked here

        Ok(())
    }

    fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.inputs
            .iter()
            .map(|resource| resource.note.get_nf().unwrap())
            .collect()
    }

    fn get_output_cms(&self) -> Vec<NoteCommitment> {
        self.outputs
            .iter()
            .map(|resource| resource.note.commitment())
            .collect()
    }

    fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        vec![ValueCommitment::from_tranparent_resources(
            &self.inputs,
            &self.outputs,
        )]
    }

    fn get_anchors(&self) -> Vec<Anchor> {
        let mut anchors = Vec::new();
        for input in self.inputs.iter() {
            if input.note.is_merkle_checked {
                if let Some(path) = &input.merkle_path {
                    anchors.push(input.note.calculate_root(path));
                }
            }
        }
        anchors
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InputResource {
    pub note: Note,
    // Only normal notes need the path, while dummy(intent and padding) notes don't need the path to calculate the anchor.
    pub merkle_path: Option<MerklePath>,
    // TODO: figure out transparent vp reprentation and how to execute it.
    //     pub static_vp:
    //     pub dynamic_vps:
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OutputResource {
    pub note: Note,
    // TODO: figure out transparent vp reprentation and how to execute it.
    //     pub static_vp:
    //     pub dynamic_vps:
}

#[cfg(test)]
pub mod testing {
    use crate::{
        constant::TAIGA_COMMITMENT_TREE_DEPTH, merkle_tree::MerklePath, note::tests::random_note,
        transparent_ptx::*,
    };
    use rand::rngs::OsRng;

    // No transparent vp included
    pub fn create_transparent_ptx() -> TransparentPartialTransaction {
        let mut rng = OsRng;
        let input_resource_1 = {
            let note = random_note(&mut rng);
            let merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
            InputResource {
                note,
                merkle_path: Some(merkle_path),
            }
        };
        let output_resource_1 = {
            let mut note = random_note(&mut rng);
            // Adjust the random note to keep the balance
            note.note_type = input_resource_1.note.note_type;
            note.value = input_resource_1.note.value;
            OutputResource { note }
        };

        let input_resource_2 = {
            let mut note = random_note(&mut rng);
            note.is_merkle_checked = false;
            InputResource {
                note,
                merkle_path: None,
            }
        };
        let output_resource_2 = {
            let mut note = random_note(&mut rng);
            // Adjust the random note to keep the balance
            note.note_type = input_resource_2.note.note_type;
            note.value = input_resource_2.note.value;
            OutputResource { note }
        };

        TransparentPartialTransaction::new(
            vec![input_resource_1, input_resource_2],
            vec![output_resource_1, output_resource_2],
            vec![],
            &mut rng,
        )
    }
}
