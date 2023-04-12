use crate::action::{ActionInfo, ActionInstance};
use crate::binding_signature::*;
use crate::circuit::vp_circuit::{VPVerifyingInfo, ValidityPredicateVerifyingInfo};
use crate::constant::{
    ACTION_CIRCUIT_PARAMS_SIZE, ACTION_PROVING_KEY, ACTION_VERIFYING_KEY, NUM_NOTE,
    SETUP_PARAMS_MAP, TRANSACTION_BINDING_HASH_PERSONALIZATION,
};
use crate::note::{NoteCommitment, OutputNoteInfo, SpendNoteInfo};
use crate::nullifier::Nullifier;
use crate::proof::Proof;
use crate::value_commitment::ValueCommitment;
use blake2b_simd::Params as Blake2bParams;
use core::fmt;
use ff::PrimeField;
use group::Group;
use halo2_proofs::plonk::Error;
use pasta_curves::pallas;
use rand::{CryptoRng, RngCore};
use std::fmt::Display;

#[derive(Debug)]
pub enum TransactionError {
    /// An error occurred when creating halo2 proof.
    Proof(Error),
    /// Binding signature is not valid.
    InvalidBindingSignature,
    /// Binding signature is missing.
    MissingBindingSignatures,
    /// Nullifier is not consistent between the action and the vp.
    InconsistentNullifier,
    /// Output note commitment is not consistent between the action and the vp.
    InconsistentOutputNoteCommitment,
    /// Owned note public id is not consistent between the action and the vp.
    InconsistentOwnedNotePubID,
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
            InconsistentOutputNoteCommitment => f.write_str(
                "Output note commitment is not consistent between the action and the vp",
            ),
            InconsistentOwnedNotePubID => {
                f.write_str("Owned note public id is not consistent between the action and the vp")
            }
        }
    }
}

impl From<Error> for TransactionError {
    fn from(e: Error) -> Self {
        TransactionError::Proof(e)
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    partial_txs: Vec<PartialTransaction>,
    // binding signature to check sum balance
    signature: InProgressBindingSignature,
}

#[derive(Debug, Clone)]
pub enum InProgressBindingSignature {
    Authorized(BindingSignature),
    Unauthorized(BindingSigningKey),
}

#[derive(Debug, Clone)]
pub struct PartialTransaction {
    actions: [ActionVerifyingInfo; NUM_NOTE],
    spends: [NoteVPVerifyingInfoSet; NUM_NOTE],
    outputs: [NoteVPVerifyingInfoSet; NUM_NOTE],
}

#[derive(Debug, Clone)]
pub struct ActionVerifyingInfo {
    action_proof: Proof,
    action_instance: ActionInstance,
}

#[derive(Debug, Clone)]
pub struct NoteVPVerifyingInfoSet {
    app_vp_verifying_info: VPVerifyingInfo,
    app_dynamic_vp_verifying_info: Vec<VPVerifyingInfo>,
    // TODO: add verifier proof and according public inputs.
    // When the verifier proof is added, we may need to reconsider the structure of `VPVerifyingInfo`
}

impl Transaction {
    pub fn build(partial_txs: Vec<PartialTransaction>, rcv_vec: Vec<pallas::Scalar>) -> Self {
        let sk = rcv_vec
            .iter()
            .fold(pallas::Scalar::zero(), |acc, rcv| acc + rcv);
        let signature = InProgressBindingSignature::Unauthorized(BindingSigningKey::from(sk));
        Self {
            partial_txs,
            signature,
        }
    }

    pub fn binding_sign<R: RngCore + CryptoRng>(&mut self, rng: R) {
        if let InProgressBindingSignature::Unauthorized(sk) = self.signature.clone() {
            let vk = self.get_binding_vk();
            assert_eq!(vk, sk.get_vk(), "The notes value is unbalanced");
            let sig_hash = self.commitment();
            let signature = sk.sign(rng, &sig_hash);
            self.signature = InProgressBindingSignature::Authorized(signature);
        }
    }

    fn commitment(&self) -> [u8; 32] {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(TRANSACTION_BINDING_HASH_PERSONALIZATION)
            .to_state();
        self.get_nullifiers().iter().for_each(|nf| {
            h.update(&nf.to_bytes());
        });
        self.get_output_cms().iter().for_each(|cm| {
            h.update(&cm.to_bytes());
        });
        self.get_value_commitments().iter().for_each(|vc| {
            h.update(&vc.to_bytes());
        });
        self.get_value_anchors().iter().for_each(|anchor| {
            h.update(&anchor.to_repr());
        });
        h.finalize().as_bytes().try_into().unwrap()
    }

    pub fn add_partial_tx(&mut self, ptx: PartialTransaction) {
        self.partial_txs.push(ptx);
    }

    pub fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_nullifiers())
            .collect()
    }

    pub fn get_output_cms(&self) -> Vec<NoteCommitment> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_output_cms())
            .collect()
    }

    pub fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_value_commitments())
            .collect()
    }

    pub fn get_value_anchors(&self) -> Vec<pallas::Base> {
        self.partial_txs
            .iter()
            .flat_map(|ptx| ptx.get_anchors())
            .collect()
    }

    pub fn get_binding_vk(&self) -> BindingVerificationKey {
        let vk = self
            .get_value_commitments()
            .iter()
            .fold(pallas::Point::identity(), |acc, cv| acc + cv.inner());

        BindingVerificationKey::from(vk)
    }

    //
    pub fn verify_proofs(&self) -> Result<(), Error> {
        for partial_tx in self.partial_txs.iter() {
            partial_tx.verify()?;
        }

        Ok(())
    }

    pub fn verify_binding_sig(&self) -> Result<(), TransactionError> {
        let binding_vk = self.get_binding_vk();
        let sig_hash = self.commitment();
        if let InProgressBindingSignature::Authorized(sig) = self.signature.clone() {
            binding_vk
                .verify(&sig_hash, &sig)
                .map_err(|_| TransactionError::InvalidBindingSignature)?;
        } else {
            return Err(TransactionError::MissingBindingSignatures);
        }

        Ok(())
    }

    pub fn public_inputs_check(&self) -> Result<(), TransactionError> {
        for partial_tx in self.partial_txs.iter() {
            // nullifier check
            partial_tx.check_nullifiers()?;
            // output note commitment check
            partial_tx.check_note_commitments()?;
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn execute(
        &self,
    ) -> Result<(Vec<Nullifier>, Vec<NoteCommitment>, Vec<pallas::Base>), TransactionError> {
        // Verify proofs
        self.verify_proofs()?;

        // Verify binding signature
        self.verify_binding_sig()?;

        // Public inputs check
        self.public_inputs_check()?;

        // Return Nullifiers to check double-spent, NoteCommitments to store, anchors to check the root-existence
        Ok((
            self.get_nullifiers(),
            self.get_output_cms(),
            self.get_value_anchors(),
        ))
    }
}

impl PartialTransaction {
    pub fn build<R: RngCore>(
        spend_info: [SpendNoteInfo; NUM_NOTE],
        output_info: [OutputNoteInfo; NUM_NOTE],
        mut rng: R,
    ) -> (Self, pallas::Scalar) {
        let spends: Vec<NoteVPVerifyingInfoSet> = spend_info
            .iter()
            .map(|spend_note| {
                NoteVPVerifyingInfoSet::build(
                    spend_note.get_app_vp_verifying_info(),
                    spend_note.get_app_vp_verifying_info_dynamic(),
                )
            })
            .collect();
        let outputs: Vec<NoteVPVerifyingInfoSet> = output_info
            .iter()
            .map(|output_note| {
                NoteVPVerifyingInfoSet::build(
                    output_note.get_app_vp_verifying_info(),
                    output_note.get_app_vp_verifying_info_dynamic(),
                )
            })
            .collect();
        let mut rcv_sum = pallas::Scalar::zero();
        let actions: Vec<ActionVerifyingInfo> = spend_info
            .into_iter()
            .zip(output_info.into_iter())
            .map(|(spend, output)| {
                let action_info = ActionInfo::new(spend, output, &mut rng);
                rcv_sum += action_info.get_rcv();
                ActionVerifyingInfo::create(action_info, &mut rng).unwrap()
            })
            .collect();

        (
            Self {
                actions: actions.try_into().unwrap(),
                spends: spends.try_into().unwrap(),
                outputs: outputs.try_into().unwrap(),
            },
            rcv_sum,
        )
    }

    pub fn verify(&self) -> Result<(), Error> {
        // Verify action proofs
        for verifying_info in self.actions.iter() {
            verifying_info.verify()?;
        }

        // Verify proofs in spend notes
        for verifying_info in self.spends.iter() {
            verifying_info.verify()?;
        }
        // Verify proofs in output notes
        for verifying_info in self.outputs.iter() {
            verifying_info.verify()?;
        }

        Ok(())
    }

    pub fn get_nullifiers(&self) -> Vec<Nullifier> {
        self.actions
            .iter()
            .map(|action| action.action_instance.nf)
            .collect()
    }

    pub fn get_output_cms(&self) -> Vec<NoteCommitment> {
        self.actions
            .iter()
            .map(|action| action.action_instance.cm)
            .collect()
    }

    pub fn get_value_commitments(&self) -> Vec<ValueCommitment> {
        self.actions
            .iter()
            .map(|action| action.action_instance.cv_net)
            .collect()
    }

    pub fn get_anchors(&self) -> Vec<pallas::Base> {
        self.actions
            .iter()
            .map(|action| action.action_instance.anchor)
            .collect()
    }

    pub fn check_nullifiers(&self) -> Result<(), TransactionError> {
        let action_nfs = self.get_nullifiers();
        for vp_info in self.spends.iter() {
            for nfs in vp_info.get_nullifiers().iter() {
                // Check the vp actually uses the spend notes from action circuits.
                if !((action_nfs[0].inner() == nfs[0] && action_nfs[1].inner() == nfs[1])
                    || (action_nfs[0].inner() == nfs[1] && action_nfs[1].inner() == nfs[0]))
                {
                    return Err(TransactionError::InconsistentNullifier);
                }
            }
        }

        for (vp_info, action_nf) in self.spends.iter().zip(action_nfs.iter()) {
            // Check the app vp and the sub vps use the same owned_note_id in one note
            let owned_note_id = vp_info.app_vp_verifying_info.get_owned_note_pub_id();
            for logic_vp_verifying_info in vp_info.app_dynamic_vp_verifying_info.iter() {
                if owned_note_id != logic_vp_verifying_info.get_owned_note_pub_id() {
                    return Err(TransactionError::InconsistentOwnedNotePubID);
                }
            }

            // Check the owned_note_id that vp uses is consistent with the nf from the action circuit
            if owned_note_id != action_nf.inner() {
                return Err(TransactionError::InconsistentOwnedNotePubID);
            }
        }
        Ok(())
    }

    pub fn check_note_commitments(&self) -> Result<(), TransactionError> {
        let action_cms = self.get_output_cms();
        for vp_info in self.outputs.iter() {
            for cms in vp_info.get_note_commitments().iter() {
                // Check the vp actually uses the output notes from action circuits.
                if !((action_cms[0].get_x() == cms[0] && action_cms[1].get_x() == cms[1])
                    && (action_cms[0].get_x() == cms[1] && action_cms[1].get_x() == cms[0]))
                {
                    return Err(TransactionError::InconsistentOutputNoteCommitment);
                }
            }
        }

        for (vp_info, action_cm) in self.outputs.iter().zip(action_cms.iter()) {
            // Check that the app vp and the sub vps use the same owned_note_id in one note
            let owned_note_id = vp_info.app_vp_verifying_info.get_owned_note_pub_id();
            for logic_vp_verifying_info in vp_info.app_dynamic_vp_verifying_info.iter() {
                if owned_note_id != logic_vp_verifying_info.get_owned_note_pub_id() {
                    return Err(TransactionError::InconsistentOwnedNotePubID);
                }
            }

            // Check the owned_note_id that vp uses is consistent with the cm from the action circuit
            if owned_note_id != action_cm.get_x() {
                return Err(TransactionError::InconsistentOwnedNotePubID);
            }
        }
        Ok(())
    }
}

impl ActionVerifyingInfo {
    pub fn create<R: RngCore>(action_info: ActionInfo, mut rng: R) -> Result<Self, Error> {
        let (action_instance, circuit) = action_info.build();
        let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
        let action_proof = Proof::create(
            &ACTION_PROVING_KEY,
            params,
            circuit,
            &[&action_instance.to_instance()],
            &mut rng,
        )
        .unwrap();
        Ok(Self {
            action_proof,
            action_instance,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
        self.action_proof.verify(
            &ACTION_VERIFYING_KEY,
            params,
            &[&self.action_instance.to_instance()],
        )
    }
}

impl NoteVPVerifyingInfoSet {
    pub fn new(
        app_vp_verifying_info: VPVerifyingInfo,
        app_dynamic_vp_verifying_info: Vec<VPVerifyingInfo>,
    ) -> Self {
        Self {
            app_vp_verifying_info,
            app_dynamic_vp_verifying_info,
        }
    }

    pub fn build(
        app_vp_verifying_info: Box<dyn ValidityPredicateVerifyingInfo>,
        app_vp_verifying_info_dynamic: Vec<Box<dyn ValidityPredicateVerifyingInfo>>,
    ) -> Self {
        let app_vp_verifying_info = app_vp_verifying_info.get_verifying_info();

        let app_dynamic_vp_verifying_info = app_vp_verifying_info_dynamic
            .into_iter()
            .map(|verifying_info| verifying_info.get_verifying_info())
            .collect();

        Self {
            app_vp_verifying_info,
            app_dynamic_vp_verifying_info,
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        // Verify application vp proof
        self.app_vp_verifying_info.verify()?;

        // Verify application dynamic vp proofs
        for verify_info in self.app_dynamic_vp_verifying_info.iter() {
            verify_info.verify()?;
        }

        // TODO: Verify vp verifier proofs

        Ok(())
    }

    pub fn get_nullifiers(&self) -> Vec<[pallas::Base; NUM_NOTE]> {
        let mut nfs = vec![self.app_vp_verifying_info.get_nullifiers()];
        self.app_dynamic_vp_verifying_info
            .iter()
            .for_each(|vp_info| nfs.push(vp_info.get_nullifiers()));
        nfs
    }

    pub fn get_note_commitments(&self) -> Vec<[pallas::Base; NUM_NOTE]> {
        let mut cms = vec![self.app_vp_verifying_info.get_note_commitments()];
        self.app_dynamic_vp_verifying_info
            .iter()
            .for_each(|vp_info| cms.push(vp_info.get_note_commitments()));
        cms
    }
}

#[test]
fn test_transaction_creation() {
    use crate::{
        circuit::vp_examples::TrivialValidityPredicateCircuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH,
        merkle_tree::MerklePath,
        note::{Note, OutputNoteInfo, SpendNoteInfo},
        nullifier::{Nullifier, NullifierKeyCom},
        utils::poseidon_hash,
    };
    use ff::Field;
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    // Create empty vp circuit without note info
    let trivial_vp_circuit = TrivialValidityPredicateCircuit::default();
    let trivail_vp_vk = trivial_vp_circuit.get_vp_vk();

    // Generate notes
    let spend_note_1 = {
        let app_data_static = pallas::Base::zero();
        // TODO: add real application dynamic vps and encode them to app_data_dynamic later.
        let app_dynamic_vp_vk = vec![trivail_vp_vk.clone(), trivail_vp_vk.clone()];
        // Encode the app_dynamic_vp_vk into app_data_dynamic
        // The encoding method is flexible and defined in the application vp.
        // Use poseidon hash to encode the two dynamic vps here
        let app_data_dynamic = poseidon_hash(
            app_dynamic_vp_vk[0].get_compressed(),
            app_dynamic_vp_vk[1].get_compressed(),
        );
        let app_vk = trivail_vp_vk.clone();
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        let value = 5000u64;
        let nk_com = NullifierKeyCom::rand(&mut rng);
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let is_merkle_checked = true;
        Note::new(
            app_vk,
            app_data_static,
            app_data_dynamic,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked,
        )
    };
    let output_note_1 = {
        let app_data_static = pallas::Base::zero();
        // TODO: add real application dynamic vps and encode them to app_data_dynamic later.
        // If the dynamic vp is not used, set app_data_dynamic pallas::Base::zero() by defualt.
        let app_data_dynamic = pallas::Base::zero();
        let rho = spend_note_1.get_nf().unwrap();
        let value = 5000u64;
        let nk_com = NullifierKeyCom::rand(&mut rng);
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let is_merkle_checked = true;
        Note::new(
            trivail_vp_vk,
            app_data_static,
            app_data_dynamic,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked,
        )
    };
    let spend_note_2 = spend_note_1.clone();
    let output_note_2 = output_note_1.clone();

    // Generate note info
    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
    // Create vp circuit and fulfill the note info
    let mut trivial_vp_circuit = TrivialValidityPredicateCircuit {
        owned_note_pub_id: spend_note_1.get_nf().unwrap().inner(),
        spend_notes: [spend_note_1.clone(), spend_note_2.clone()],
        output_notes: [output_note_1.clone(), output_note_2.clone()],
    };
    let spend_app_vp_verifying_info_1 = Box::new(trivial_vp_circuit.clone());
    let trivial_app_logic_1: Box<dyn ValidityPredicateVerifyingInfo> =
        Box::new(trivial_vp_circuit.clone());
    let trivial_app_logic_2 = Box::new(trivial_vp_circuit.clone());
    let trivial_app_vp_verifying_info_dynamic = vec![trivial_app_logic_1, trivial_app_logic_2];
    let spend_note_info_1 = SpendNoteInfo::new(
        spend_note_1,
        merkle_path.clone(),
        spend_app_vp_verifying_info_1,
        trivial_app_vp_verifying_info_dynamic.clone(),
    );
    // The following notes use empty logic vps and use app_data_dynamic with pallas::Base::zero() by default.
    trivial_vp_circuit.owned_note_pub_id = spend_note_2.get_nf().unwrap().inner();
    let spend_app_vp_verifying_info_2 = Box::new(trivial_vp_circuit.clone());
    let app_vp_verifying_info_dynamic = vec![];
    let spend_note_info_2 = SpendNoteInfo::new(
        spend_note_2,
        merkle_path,
        spend_app_vp_verifying_info_2,
        app_vp_verifying_info_dynamic.clone(),
    );

    trivial_vp_circuit.owned_note_pub_id = output_note_1.commitment().get_x();
    let output_app_vp_verifying_info_1 = Box::new(trivial_vp_circuit.clone());
    let output_note_info_1 = OutputNoteInfo::new(
        output_note_1,
        output_app_vp_verifying_info_1,
        app_vp_verifying_info_dynamic.clone(),
    );

    trivial_vp_circuit.owned_note_pub_id = output_note_2.commitment().get_x();
    let output_app_vp_verifying_info_2 = Box::new(trivial_vp_circuit);
    let output_note_info_2 = OutputNoteInfo::new(
        output_note_2,
        output_app_vp_verifying_info_2,
        app_vp_verifying_info_dynamic,
    );

    // Create partial tx
    let (ptx, rcv) = PartialTransaction::build(
        [spend_note_info_1, spend_note_info_2],
        [output_note_info_1, output_note_info_2],
        &mut rng,
    );

    // Create tx
    let mut tx = Transaction::build(vec![ptx], vec![rcv]);
    tx.binding_sign(rng);
    tx.execute().unwrap();
}
