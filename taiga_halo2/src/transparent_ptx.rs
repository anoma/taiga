use crate::{
    circuit::resource_logic_bytecode::ApplicationByteCode, compliance::ComplianceInfo,
    constant::NUM_RESOURCE, delta_commitment::DeltaCommitment, error::TransactionError,
    executable::Executable, merkle_tree::Anchor, nullifier::Nullifier,
    resource::ResourceCommitment,
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
    compliances: Vec<ComplianceInfo>,
    input_resource_app: Vec<ApplicationByteCode>,
    output_resource_app: Vec<ApplicationByteCode>,
    hints: Vec<u8>,
}

impl TransparentPartialTransaction {
    pub fn new(
        compliances: Vec<ComplianceInfo>,
        input_resource_app: Vec<ApplicationByteCode>,
        output_resource_app: Vec<ApplicationByteCode>,
        hints: Vec<u8>,
    ) -> Self {
        assert_eq!(compliances.len(), NUM_RESOURCE);
        assert_eq!(input_resource_app.len(), NUM_RESOURCE);
        assert_eq!(output_resource_app.len(), NUM_RESOURCE);

        Self {
            compliances,
            input_resource_app,
            output_resource_app,
            hints,
        }
    }
}

impl Executable for TransparentPartialTransaction {
    fn execute(&self) -> Result<(), TransactionError> {
        // check resource logics, nullifiers, and resource commitments
        let compliance_nfs = self.get_nullifiers();
        let compliance_cms = self.get_output_cms();
        let compliance_resource_merkle_root = self.get_resource_merkle_root();
        for (resource_logic, nf) in self.input_resource_app.iter().zip(compliance_nfs.iter()) {
            let self_resource_id =
                resource_logic.verify_transparently(&compliance_resource_merkle_root)?;
            // Make sure all resource logics are checked
            if self_resource_id != nf.inner() {
                return Err(TransactionError::InconsistentSelfResourceID);
            }
        }

        for (resource_logic, cm) in self.output_resource_app.iter().zip(compliance_cms.iter()) {
            let self_resource_id =
                resource_logic.verify_transparently(&compliance_resource_merkle_root)?;
            // Make sure all resource logics are checked
            if self_resource_id != cm.inner() {
                return Err(TransactionError::InconsistentSelfResourceID);
            }
        }

        Ok(())
    }

    // get nullifiers from compliances
    fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.compliances
            .iter()
            .map(|compliance| compliance.get_input_resource_nullifier())
            .collect()
    }

    // get output cms from compliances
    fn get_output_cms(&self) -> Vec<ResourceCommitment> {
        self.compliances
            .iter()
            .map(|compliance| compliance.get_output_resource_cm())
            .collect()
    }

    fn get_delta_commitments(&self) -> Vec<DeltaCommitment> {
        self.compliances
            .iter()
            .map(|compliance| compliance.get_delta_commitment(&pallas::Scalar::zero()))
            .collect()
    }

    fn get_anchors(&self) -> Vec<Anchor> {
        // TODO: We have easier way to check the anchor in transparent scenario, but keep consistent with shielded right now.
        // TODO: we can skip the root if the is_ephemeral flag is true?
        self.compliances
            .iter()
            .map(|compliance| compliance.calculate_root())
            .collect()
    }
}

#[cfg(test)]
#[cfg(feature = "borsh")]
pub mod testing {
    use crate::{
        circuit::resource_logic_examples::TrivialResourceLogicCircuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH, merkle_tree::MerklePath,
        resource::tests::random_resource, resource_tree::ResourceMerkleTreeLeaves,
        transparent_ptx::*,
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
        let compliance_1 = ComplianceInfo::new(
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
        let compliance_2 = ComplianceInfo::new(
            input_resource_2,
            merkle_path_2,
            None,
            &mut output_resource_2,
            &mut rng,
        );

        // Collect resource merkle leaves
        let input_resource_nf_1 = input_resource_1.get_nf().unwrap().inner();
        let output_resource_cm_1 = output_resource_1.commitment().inner();
        let input_resource_nf_2 = input_resource_2.get_nf().unwrap().inner();
        let output_resource_cm_2 = output_resource_2.commitment().inner();
        let resource_merkle_tree = ResourceMerkleTreeLeaves::new(vec![
            input_resource_nf_1,
            output_resource_cm_1,
            input_resource_nf_2,
            output_resource_cm_2,
        ]);

        // construct applications
        let input_resource_1_app = {
            let input_resource_path_1 = resource_merkle_tree
                .generate_path(input_resource_nf_1)
                .unwrap();
            let input_resource_application_logic_1 =
                TrivialResourceLogicCircuit::new(input_resource_1, input_resource_path_1);

            ApplicationByteCode::new(input_resource_application_logic_1.to_bytecode(), vec![])
        };

        let input_resource_2_app = {
            let input_resource_path_2 = resource_merkle_tree
                .generate_path(input_resource_nf_2)
                .unwrap();
            let input_resource_application_logic_2 =
                TrivialResourceLogicCircuit::new(input_resource_2, input_resource_path_2);

            ApplicationByteCode::new(input_resource_application_logic_2.to_bytecode(), vec![])
        };

        let output_resource_1_app = {
            let output_resource_path_1 = resource_merkle_tree
                .generate_path(output_resource_cm_1)
                .unwrap();
            let output_resource_application_logic_1 =
                TrivialResourceLogicCircuit::new(output_resource_1, output_resource_path_1);

            ApplicationByteCode::new(output_resource_application_logic_1.to_bytecode(), vec![])
        };

        let output_resource_2_app = {
            let output_resource_path_2 = resource_merkle_tree
                .generate_path(output_resource_cm_2)
                .unwrap();
            let output_resource_application_logic_2 =
                TrivialResourceLogicCircuit::new(output_resource_2, output_resource_path_2);

            ApplicationByteCode::new(output_resource_application_logic_2.to_bytecode(), vec![])
        };

        TransparentPartialTransaction::new(
            vec![compliance_1, compliance_2],
            vec![input_resource_1_app, input_resource_2_app],
            vec![output_resource_1_app, output_resource_2_app],
            vec![],
        )
    }
}
