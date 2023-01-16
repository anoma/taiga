use crate::action::{ActionInfo, ActionInstance};
use crate::bindnig_signature::*;
use crate::circuit::vp_circuit::{VPVerifyingInfo, ValidityPredicateInfo};
use crate::constant::{
    ACTION_CIRCUIT_PARAMS_SIZE, ACTION_PROVING_KEY, ACTION_VERIFYING_KEY, NUM_NOTE,
    SETUP_PARAMS_MAP, TRANSACTION_BINDING_HASH_PERSONALIZATION,
};
use crate::note::{NoteCommitment, OutputNoteInfo, SpendNoteInfo};
use crate::nullifier::Nullifier;
use crate::value_commitment::ValueCommitment;
use blake2b_simd::Params as Blake2bParams;
use core::fmt;
use ff::PrimeField;
use group::Group;
use halo2_proofs::{
    plonk::{create_proof, verify_proof, Error, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};
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
}

impl Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TransactionError::*;
        match self {
            Proof(e) => f.write_str(&format!("Proof error: {e}")),
            InvalidBindingSignature => f.write_str("Binding signature was invalid"),
            MissingBindingSignatures => f.write_str("Binding signature is missing"),
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
    action_proof: Vec<u8>,
    action_instance: ActionInstance,
}

#[derive(Debug, Clone)]
pub struct NoteVPVerifyingInfoSet {
    app_vp_verifying_info: VPVerifyingInfo,
    app_logic_vp_verifying_info: Vec<VPVerifyingInfo>,
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

    #[allow(clippy::type_complexity)]
    pub fn execute(
        &self,
    ) -> Result<(Vec<Nullifier>, Vec<NoteCommitment>, Vec<pallas::Base>), TransactionError> {
        // Verify proofs
        self.verify_proofs()?;

        // Verify binding signature
        self.verify_binding_sig()?;

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
                    spend_note.get_app_vp_proving_info(),
                    spend_note.get_app_logic_vp_proving_info(),
                )
            })
            .collect();
        let outputs: Vec<NoteVPVerifyingInfoSet> = output_info
            .iter()
            .map(|output_note| {
                NoteVPVerifyingInfoSet::build(
                    output_note.get_app_vp_proving_info(),
                    output_note.get_app_logic_vp_proving_info(),
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
}

impl ActionVerifyingInfo {
    pub fn create<R: RngCore>(action_info: ActionInfo, mut rng: R) -> Result<Self, Error> {
        let (action_instance, circuit) = action_info.build();
        let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        create_proof(
            params,
            &ACTION_PROVING_KEY,
            &[circuit],
            &[&[&action_instance.to_instance()]],
            &mut rng,
            &mut transcript,
        )?;
        let action_proof = transcript.finalize();
        Ok(Self {
            action_proof,
            action_instance,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::init(&self.action_proof[..]);
        verify_proof(
            params,
            &ACTION_VERIFYING_KEY,
            strategy,
            &[&[&self.action_instance.to_instance()]],
            &mut transcript,
        )
    }
}

impl NoteVPVerifyingInfoSet {
    pub fn new(
        app_vp_verifying_info: VPVerifyingInfo,
        app_logic_vp_verifying_info: Vec<VPVerifyingInfo>,
    ) -> Self {
        Self {
            app_vp_verifying_info,
            app_logic_vp_verifying_info,
        }
    }

    pub fn build(
        app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
        app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
    ) -> Self {
        let app_vp_verifying_info = app_vp_proving_info.get_verifying_info();

        let app_logic_vp_verifying_info = app_logic_vp_proving_info
            .into_iter()
            .map(|proving_info| proving_info.get_verifying_info())
            .collect();

        Self {
            app_vp_verifying_info,
            app_logic_vp_verifying_info,
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        // Verify application vp proof
        self.app_vp_verifying_info.verify()?;

        // Verify application logic vp proofs
        for verify_info in self.app_logic_vp_verifying_info.iter() {
            verify_info.verify()?;
        }

        // TODO: Verify vp verifier proofs

        Ok(())
    }
}

#[test]
fn test_transaction_creation() {
    use crate::{
        circuit::vp_examples::TrivialValidityPredicateCircuit,
        constant::TAIGA_COMMITMENT_TREE_DEPTH,
        merkle_tree::MerklePath,
        note::{Note, OutputNoteInfo, SpendNoteInfo},
        nullifier::Nullifier,
        nullifier_key::NullifierKeyCom,
    };
    use ff::Field;
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    // Create empty vp circuit without note info
    let trivial_vp_circuit = TrivialValidityPredicateCircuit::default();
    let trivail_vp_description = trivial_vp_circuit.get_vp_description();

    // Generate notes
    let spend_note_1 = {
        let vp_data = pallas::Base::zero();
        // TODO: add real application logic vps and encode them to vp_data_nonhashed later.
        let vp_data_nonhashed = pallas::Base::zero();
        let application_vp = trivail_vp_description.clone();
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        let value = 5000u64;
        let nk_com = NullifierKeyCom::rand(&mut rng);
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let is_merkle_checked = true;
        Note::new(
            application_vp,
            vp_data,
            vp_data_nonhashed,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked,
            vec![0u8; 32],
        )
    };
    let output_note_1 = {
        let vp_data = pallas::Base::zero();
        // TODO: add real application logic vps and encode them to vp_data_nonhashed later.
        let vp_data_nonhashed = pallas::Base::zero();
        let rho = spend_note_1.get_nf().unwrap();
        let value = 5000u64;
        let nk_com = NullifierKeyCom::rand(&mut rng);
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let is_merkle_checked = true;
        Note::new(
            trivail_vp_description,
            vp_data,
            vp_data_nonhashed,
            value,
            nk_com,
            rho,
            psi,
            rcm,
            is_merkle_checked,
            vec![0u8; 32],
        )
    };
    let spend_note_2 = spend_note_1.clone();
    let output_note_2 = output_note_1.clone();

    // Generate note info
    let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
    // Create vp circuit and fulfill the note info
    let app_vp_circuit = TrivialValidityPredicateCircuit {
        spend_notes: [spend_note_1.clone(), spend_note_2.clone()],
        output_notes: [output_note_1.clone(), output_note_2.clone()],
    };
    let app_vp_proving_info = Box::new(app_vp_circuit);
    let app_logic_vp_proving_info = vec![];
    let spend_note_info_1 = SpendNoteInfo::new(
        spend_note_1,
        merkle_path.clone(),
        app_vp_proving_info.clone(),
        app_logic_vp_proving_info.clone(),
    );
    let spend_note_info_2 = SpendNoteInfo::new(
        spend_note_2,
        merkle_path,
        app_vp_proving_info.clone(),
        app_logic_vp_proving_info.clone(),
    );
    let output_note_info_1 = OutputNoteInfo::new(
        output_note_1,
        app_vp_proving_info.clone(),
        app_logic_vp_proving_info.clone(),
    );
    let output_note_info_2 = OutputNoteInfo::new(
        output_note_2,
        app_vp_proving_info,
        app_logic_vp_proving_info,
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
