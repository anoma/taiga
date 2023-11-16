use crate::{
    action::ActionInfo, circuit::vp_bytecode::ApplicationByteCode, constant::NUM_NOTE,
    error::TransactionError, executable::Executable, merkle_tree::Anchor, note::NoteCommitment,
    nullifier::Nullifier, value_commitment::ValueCommitment,
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
    actions: Vec<ActionInfo>,
    input_note_app: Vec<ApplicationByteCode>,
    output_note_app: Vec<ApplicationByteCode>,
    hints: Vec<u8>,
}

impl TransparentPartialTransaction {
    pub fn new(
        actions: Vec<ActionInfo>,
        input_note_app: Vec<ApplicationByteCode>,
        output_note_app: Vec<ApplicationByteCode>,
        hints: Vec<u8>,
    ) -> Self {
        assert_eq!(actions.len(), NUM_NOTE);
        assert_eq!(input_note_app.len(), NUM_NOTE);
        assert_eq!(output_note_app.len(), NUM_NOTE);

        Self {
            actions,
            input_note_app,
            output_note_app,
            hints,
        }
    }
}

impl Executable for TransparentPartialTransaction {
    fn execute(&self) -> Result<(), TransactionError> {
        // check VPs, nullifiers, and note commitments
        let action_nfs = self.get_nullifiers();
        let action_cms = self.get_output_cms();
        for (vp, nf) in self.input_note_app.iter().zip(action_nfs.iter()) {
            let owned_note_id = vp.verify_transparently(&action_nfs, &action_cms)?;
            // Check all notes are checked
            if owned_note_id != nf.inner() {
                return Err(TransactionError::InconsistentOwnedNotePubID);
            }
        }

        for (vp, cm) in self.output_note_app.iter().zip(action_cms.iter()) {
            let owned_note_id = vp.verify_transparently(&action_nfs, &action_cms)?;
            // Check all notes are checked
            if owned_note_id != cm.inner() {
                return Err(TransactionError::InconsistentOwnedNotePubID);
            }
        }

        Ok(())
    }

    // get nullifiers from actions
    fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.actions
            .iter()
            .map(|action| action.get_input_note_nullifer())
            .collect()
    }

    // get output cms from actions
    fn get_output_cms(&self) -> Vec<NoteCommitment> {
        self.actions
            .iter()
            .map(|action| action.get_output_note_cm())
            .collect()
    }

    fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        self.actions
            .iter()
            .map(|action| action.get_value_commitment(&pallas::Scalar::zero()))
            .collect()
    }

    fn get_anchors(&self) -> Vec<Anchor> {
        // TODO: We have easier way to check the anchor in transparent scenario, but keep consistent with sheilded right now.
        // TODO: we can skip the root if the is_merkle_checked flag is false?
        self.actions
            .iter()
            .map(|action| action.calcute_root())
            .collect()
    }
}

#[cfg(test)]
#[cfg(feature = "borsh")]
pub mod testing {
    use crate::{
        circuit::vp_examples::TrivialValidityPredicateCircuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH, merkle_tree::MerklePath, note::tests::random_note,
        transparent_ptx::*,
    };
    use rand::rngs::OsRng;

    pub fn create_transparent_ptx() -> TransparentPartialTransaction {
        let mut rng = OsRng;
        // construct notes
        let input_note_1 = random_note(&mut rng);
        let mut output_note_1 = {
            let mut note = random_note(&mut rng);
            note.note_type = input_note_1.note_type;
            note.value = input_note_1.value;
            note
        };
        let merkle_path_1 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let action_1 = ActionInfo::new(
            input_note_1,
            merkle_path_1,
            None,
            &mut output_note_1,
            &mut rng,
        );

        let input_note_2 = random_note(&mut rng);
        let mut output_note_2 = {
            let mut note = random_note(&mut rng);
            note.note_type = input_note_2.note_type;
            note.value = input_note_2.value;
            note
        };
        let merkle_path_2 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let action_2 = ActionInfo::new(
            input_note_2,
            merkle_path_2,
            None,
            &mut output_note_2,
            &mut rng,
        );

        // construct applications
        let input_note_1_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_note_1.get_nf().unwrap().inner(),
                [input_note_1, input_note_2],
                [output_note_1, output_note_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let input_note_2_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_note_2.get_nf().unwrap().inner(),
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

        TransparentPartialTransaction::new(
            vec![action_1, action_2],
            vec![input_note_1_app, input_note_2_app],
            vec![output_note_1_app, output_note_2_app],
            vec![],
        )
    }
}
