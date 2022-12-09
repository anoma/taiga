use crate::{
    application::Application,
    circuit::{action_circuit::ActionCircuit, vp_circuit::ValidityPredicateInfo},
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{MerklePath, Node},
    note::{Note, NoteCommitment},
    nullifier::Nullifier,
    value_commitment::ValueCommitment,
};
use ff::Field;
use pasta_curves::pallas;
use rand::RngCore;

/// The action result used in transaction.
#[derive(Copy, Debug, Clone)]
pub struct ActionInstance {
    /// The root of the note commitment Merkle tree.
    pub anchor: pallas::Base,
    /// The nullifier of the spend note.
    pub nf: Nullifier,
    /// The commitment of the output note.
    pub cm: NoteCommitment,
    /// net value commitment
    pub cv_net: ValueCommitment,
    // TODO: The EncryptedNote.
    // encrypted_note,
}

/// The information to build ActionInstance and ActionCircuit.
#[derive(Clone)]
pub struct ActionInfo {
    spend: SpendNoteInfo,
    output: OutputNoteInfo,
}

#[derive(Clone)]
pub struct SpendNoteInfo {
    note: Note,
    auth_path: [(pallas::Base, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    root: pallas::Base,
    app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
    app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
}

#[derive(Clone)]
pub struct OutputNoteInfo {
    application: Application,
    value: u64,
    is_merkle_checked: bool,
    app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
    app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
}

impl ActionInstance {
    pub fn to_instance(&self) -> Vec<pallas::Base> {
        vec![
            self.nf.inner(),
            self.anchor,
            self.cm.get_x(),
            self.cv_net.get_x(),
            self.cv_net.get_y(),
        ]
    }
}

impl ActionInfo {
    pub fn new(spend: SpendNoteInfo, output: OutputNoteInfo) -> Self {
        Self { spend, output }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        use crate::circuit::vp_examples::DummyValidityPredicateCircuit;
        let spend_note = Note::dummy(&mut rng);
        let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let app_vp_proving_info = Box::new(DummyValidityPredicateCircuit::dummy(&mut rng));
        let app_logic_vp_proving_info = vec![];
        let spend_info = SpendNoteInfo::new(
            spend_note,
            merkle_path,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        );

        let output_info = OutputNoteInfo::dummy(&mut rng);

        ActionInfo::new(spend_info, output_info)
    }

    pub fn build<R: RngCore>(self, mut rng: R) -> (ActionInstance, ActionCircuit) {
        let nf = self.spend.note.get_nf();
        let psi = pallas::Base::random(&mut rng);
        let note_rcm = pallas::Scalar::random(&mut rng);
        let output_note = Note::new(
            self.output.application,
            self.output.value,
            nf,
            psi,
            note_rcm,
            self.output.is_merkle_checked,
        );

        let output_cm = output_note.commitment();
        let rcv = pallas::Scalar::random(&mut rng);

        let cv_net = ValueCommitment::new(&self.spend.note, &output_note, &rcv);
        let action = ActionInstance {
            nf,
            cm: output_cm,
            anchor: self.spend.root,
            cv_net,
        };

        let action_circuit = ActionCircuit {
            spend_note: self.spend.note,
            auth_path: self.spend.auth_path,
            output_note,
            rcv,
        };

        (action, action_circuit)
    }
}

impl SpendNoteInfo {
    pub fn new(
        note: Note,
        merkle_path: MerklePath,
        app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
        app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
    ) -> Self {
        let cm_node = Node::new(note.commitment().get_x());
        let root = merkle_path.root(cm_node).inner();
        let auth_path: [(pallas::Base, bool); TAIGA_COMMITMENT_TREE_DEPTH] =
            merkle_path.get_path().as_slice().try_into().unwrap();
        Self {
            note,
            auth_path,
            root,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        }
    }

    pub fn get_app_vp_proving_info(&self) -> Box<dyn ValidityPredicateInfo> {
        self.app_vp_proving_info.clone()
    }

    pub fn get_app_logic_vp_proving_info(&self) -> Vec<Box<dyn ValidityPredicateInfo>> {
        self.app_logic_vp_proving_info.clone()
    }
}

impl OutputNoteInfo {
    pub fn new(
        application: Application,
        value: u64,
        is_merkle_checked: bool,
        app_vp_proving_info: Box<dyn ValidityPredicateInfo>,
        app_logic_vp_proving_info: Vec<Box<dyn ValidityPredicateInfo>>,
    ) -> Self {
        Self {
            application,
            value,
            is_merkle_checked,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        use crate::circuit::vp_examples::DummyValidityPredicateCircuit;
        use rand::Rng;
        let application = Application::dummy(&mut rng);
        let value: u64 = rng.gen();
        let app_vp_proving_info = Box::new(DummyValidityPredicateCircuit::dummy(&mut rng));
        let app_logic_vp_proving_info = vec![];
        Self {
            application,
            value,
            is_merkle_checked: true,
            app_vp_proving_info,
            app_logic_vp_proving_info,
        }
    }

    pub fn get_app_vp_proving_info(&self) -> Box<dyn ValidityPredicateInfo> {
        self.app_vp_proving_info.clone()
    }

    pub fn get_app_logic_vp_proving_info(&self) -> Vec<Box<dyn ValidityPredicateInfo>> {
        self.app_logic_vp_proving_info.clone()
    }
}
