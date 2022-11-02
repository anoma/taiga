use crate::{
    app::App,
    circuit::action_circuit::ActionCircuit,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{MerklePath, Node},
    net_value_commitment::NetValueCommitment,
    note::{Note, NoteCommitment},
    nullifier::Nullifier,
    user::User,
    user::UserSendAddress,
    vp_description::ValidityPredicateDescription,
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
    /// Enable spend
    pub enable_spend: bool,
    /// Enable output
    pub enable_output: bool,
    /// net value commitment
    pub net_value_commitment: NetValueCommitment,
    // TODO: The EncryptedNote.
    // encrypted_note,
}

/// The information to build ActionInstance and ActionCircuit.
#[derive(Debug, Clone)]
pub struct ActionInfo {
    spend: SpendInfo,
    output: OutputInfo,
}

#[derive(Debug, Clone)]
pub struct SpendInfo {
    note: Note,
    auth_path: [(pallas::Base, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    root: pallas::Base,
}

#[derive(Debug, Clone)]
pub struct OutputInfo {
    addr_send_closed: UserSendAddress,
    addr_recv_vp: ValidityPredicateDescription,
    app_vp: ValidityPredicateDescription,
    app_data: pallas::Base,
    value: u64,
    is_normal: bool,
}

impl ActionInstance {
    pub fn to_instance(&self) -> Vec<pallas::Base> {
        vec![
            self.nf.inner(),
            self.anchor,
            self.cm.get_x(),
            pallas::Base::from(self.enable_spend),
            pallas::Base::from(self.enable_output),
            self.net_value_commitment.get_x(),
            self.net_value_commitment.get_y(),
        ]
    }
}

impl ActionInfo {
    pub fn new(spend: SpendInfo, output: OutputInfo) -> Self {
        Self { spend, output }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let spend_note = Note::dummy(&mut rng);
        let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let spend_info = SpendInfo::new(spend_note, merkle_path);

        let output_info = OutputInfo::dummy(&mut rng);

        ActionInfo::new(spend_info, output_info)
    }

    pub fn build<R: RngCore>(self, mut rng: R) -> (ActionInstance, ActionCircuit) {
        let nf = self.spend.note.get_nf();

        let user = User {
            send_com: self.output.addr_send_closed,
            recv_vp: self.output.addr_recv_vp,
        };
        let app = App::new(self.output.app_vp, self.output.app_data);

        let psi = pallas::Base::random(&mut rng);
        let note_rcm = pallas::Scalar::random(&mut rng);
        let output_note = Note::new(
            user,
            app,
            self.output.value,
            nf,
            psi,
            note_rcm,
            self.output.is_normal,
        );

        let output_cm = output_note.commitment();
        let enable_spend = (self.spend.note.is_normal as u64) * self.spend.note.value > 0;
        let enable_output = (self.output.is_normal as u64) * self.output.value > 0;

        let rcv = pallas::Scalar::random(&mut rng);

        let net_value_commitment = NetValueCommitment::new(&self.spend.note, &output_note, &rcv);
        let action = ActionInstance {
            nf,
            cm: output_cm,
            anchor: self.spend.root,
            enable_spend,
            enable_output,
            net_value_commitment,
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

impl SpendInfo {
    pub fn new(note: Note, merkle_path: MerklePath) -> Self {
        let cm_node = Node::new(note.commitment().get_x());
        let root = merkle_path.root(cm_node).inner();
        let auth_path: [(pallas::Base, bool); TAIGA_COMMITMENT_TREE_DEPTH] =
            merkle_path.get_path().as_slice().try_into().unwrap();
        Self {
            note,
            auth_path,
            root,
        }
    }
}

impl OutputInfo {
    pub fn new(
        addr_send_closed: UserSendAddress,
        addr_recv_vp: ValidityPredicateDescription,
        app_vp: ValidityPredicateDescription,
        app_data: pallas::Base,
        value: u64,
        is_normal: bool,
    ) -> Self {
        Self {
            addr_send_closed,
            addr_recv_vp,
            app_vp,
            app_data,
            value,
            is_normal,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        use rand::Rng;
        let addr_send_closed = UserSendAddress::from_closed(pallas::Base::random(&mut rng));
        let addr_recv_vp = ValidityPredicateDescription::dummy(&mut rng);
        let app_vp = ValidityPredicateDescription::dummy(&mut rng);
        let app_data = pallas::Base::random(&mut rng);
        let value: u64 = rng.gen();
        Self {
            addr_send_closed,
            addr_recv_vp,
            app_vp,
            app_data,
            value,
            is_normal: true,
        }
    }
}
