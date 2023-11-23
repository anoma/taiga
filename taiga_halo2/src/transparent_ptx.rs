use crate::{
    action::ActionInfo, circuit::vp_bytecode::ApplicationByteCode, constant::NUM_RESOURCE,
    delta_commitment::DeltaCommitment, error::TransactionError, executable::Executable,
    merkle_tree::Anchor, nullifier::Nullifier, resource::ResourceCommitment,
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
    input_resource_app: Vec<ApplicationByteCode>,
    output_resource_app: Vec<ApplicationByteCode>,
    hints: Vec<u8>,
}

impl TransparentPartialTransaction {
    pub fn new(
        actions: Vec<ActionInfo>,
        input_resource_app: Vec<ApplicationByteCode>,
        output_resource_app: Vec<ApplicationByteCode>,
        hints: Vec<u8>,
    ) -> Self {
        assert_eq!(actions.len(), NUM_RESOURCE);
        assert_eq!(input_resource_app.len(), NUM_RESOURCE);
        assert_eq!(output_resource_app.len(), NUM_RESOURCE);

        Self {
            actions,
            input_resource_app,
            output_resource_app,
            hints,
        }
    }
}

impl Executable for TransparentPartialTransaction {
    fn execute(&self) -> Result<(), TransactionError> {
        // check VPs, nullifiers, and resource commitments
        let action_nfs = self.get_nullifiers();
        let action_cms = self.get_output_cms();
        for (vp, nf) in self.input_resource_app.iter().zip(action_nfs.iter()) {
            let owned_resource_id = vp.verify_transparently(&action_nfs, &action_cms)?;
            // Check all resources are checked
            if owned_resource_id != nf.inner() {
                return Err(TransactionError::InconsistentOwneResourceID);
            }
        }

        for (vp, cm) in self.output_resource_app.iter().zip(action_cms.iter()) {
            let owned_resource_id = vp.verify_transparently(&action_nfs, &action_cms)?;
            // Check all resources are checked
            if owned_resource_id != cm.inner() {
                return Err(TransactionError::InconsistentOwneResourceID);
            }
        }

        Ok(())
    }

    // get nullifiers from actions
    fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.actions
            .iter()
            .map(|action| action.get_input_resource_nullifer())
            .collect()
    }

    // get output cms from actions
    fn get_output_cms(&self) -> Vec<ResourceCommitment> {
        self.actions
            .iter()
            .map(|action| action.get_output_resource_cm())
            .collect()
    }

    fn get_delta_commitments(&self) -> Vec<DeltaCommitment> {
        self.actions
            .iter()
            .map(|action| action.get_delta_commitment(&pallas::Scalar::zero()))
            .collect()
    }

    fn get_anchors(&self) -> Vec<Anchor> {
        // TODO: We have easier way to check the anchor in transparent scenario, but keep consistent with sheilded right now.
        // TODO: we can skip the root if the is_merkle_checked flag is false?
        self.actions
            .iter()
            .map(|action| action.calculate_root())
            .collect()
    }
}

#[cfg(test)]
#[cfg(feature = "borsh")]
pub mod testing {
    use crate::{
        circuit::vp_examples::TrivialValidityPredicateCircuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH, merkle_tree::MerklePath,
        resource::tests::random_resource, transparent_ptx::*,
    };
    use rand::rngs::OsRng;

    pub fn create_transparent_ptx() -> TransparentPartialTransaction {
        let mut rng = OsRng;
        // construct resources
        let input_resource_1 = random_resource(&mut rng);
        let mut output_resource_1 = {
            let mut resource = random_resource(&mut rng);
            resource.kind = input_resource_1.kind;
            resource.quantity = input_resource_1.quantity;
            resource
        };
        let merkle_path_1 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let action_1 = ActionInfo::new(
            input_resource_1,
            merkle_path_1,
            None,
            &mut output_resource_1,
            &mut rng,
        );

        let input_resource_2 = random_resource(&mut rng);
        let mut output_resource_2 = {
            let mut resource = random_resource(&mut rng);
            resource.kind = input_resource_2.kind;
            resource.quantity = input_resource_2.quantity;
            resource
        };
        let merkle_path_2 = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let action_2 = ActionInfo::new(
            input_resource_2,
            merkle_path_2,
            None,
            &mut output_resource_2,
            &mut rng,
        );

        // construct applications
        let input_resource_1_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_resource_1.get_nf().unwrap().inner(),
                [input_resource_1, input_resource_2],
                [output_resource_1, output_resource_2],
            );

            ApplicationByteCode::new(app_vp.to_bytecode(), vec![])
        };

        let input_resource_2_app = {
            let app_vp = TrivialValidityPredicateCircuit::new(
                input_resource_2.get_nf().unwrap().inner(),
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

        TransparentPartialTransaction::new(
            vec![action_1, action_2],
            vec![input_resource_1_app, input_resource_2_app],
            vec![output_resource_1_app, output_resource_2_app],
            vec![],
        )
    }
}
