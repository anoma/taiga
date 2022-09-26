use crate::{
    app::App,
    circuit::{action_circuit::ActionCircuit, circuit_parameters::CircuitParameters},
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::{MerklePath, Node},
    note::{Note, NoteCommitment},
    nullifier::Nullifier,
    user::User,
    user::UserSendAddress,
    vp_description::ValidityPredicateDescription,
};
use ff::Field;
use rand::RngCore;

/// The action result used in transaction.
#[derive(Copy, Debug, Clone)]
pub struct ActionInstance<CP: CircuitParameters> {
    /// The root of the note commitment Merkle tree.
    pub root: CP::CurveScalarField,
    /// The nullifier of the spend note.
    pub nf: Nullifier<CP>,
    /// The commitment of the output note.
    pub cm: NoteCommitment<CP>,
    // TODO: The EncryptedNote.
    // encrypted_note,
}

/// The information to build ActionInstance and ActionCircuit.
#[derive(Debug, Clone)]
pub struct ActionInfo<CP: CircuitParameters> {
    spend: SpendInfo<CP>,
    output: OutputInfo<CP>,
}

#[derive(Debug, Clone)]
pub struct SpendInfo<CP: CircuitParameters> {
    note: Note<CP>,
    auth_path: [(CP::CurveScalarField, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    root: CP::CurveScalarField,
}

#[derive(Debug, Clone)]
pub struct OutputInfo<CP: CircuitParameters> {
    addr_send_closed: UserSendAddress<CP>,
    addr_recv_vp: ValidityPredicateDescription<CP>,
    addr_app_vp: ValidityPredicateDescription<CP>,
    value: u64,
    data: CP::CurveScalarField,
}

impl<CP: CircuitParameters> ActionInstance<CP> {
    pub fn to_instance(&self) -> Vec<CP::CurveScalarField> {
        vec![self.nf.inner(), self.root, self.cm.get_x()]
    }
}

impl<CP: CircuitParameters> ActionInfo<CP> {
    pub fn new(spend: SpendInfo<CP>, output: OutputInfo<CP>) -> Self {
        Self { spend, output }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        let spend_note = Note::dummy(&mut rng);
        let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let spend_info = SpendInfo::new(spend_note, merkle_path);

        let output_info = OutputInfo::dummy(&mut rng);

        ActionInfo::new(spend_info, output_info)
    }

    pub fn build(self, rng: &mut impl RngCore) -> (ActionInstance<CP>, ActionCircuit<CP>) {
        let nf = self.spend.note.get_nf();

        let user = User {
            send_com: self.output.addr_send_closed,
            recv_vp: self.output.addr_recv_vp,
        };
        let app = App {
            app_vp: self.output.addr_app_vp,
        };

        let note_rcm = CP::InnerCurveScalarField::random(rng);
        let output_note = Note::new(user, app, self.output.value, nf, self.output.data, note_rcm);

        let output_cm = output_note.commitment();
        let action = ActionInstance {
            nf,
            cm: output_cm,
            root: self.spend.root,
        };

        let action_circuit = ActionCircuit {
            spend_note: self.spend.note,
            auth_path: self.spend.auth_path,
            output_note,
        };

        (action, action_circuit)
    }
}

impl<CP: CircuitParameters> SpendInfo<CP> {
    pub fn new(note: Note<CP>, merkle_path: MerklePath<CP::CurveScalarField>) -> Self {
        let cm_node = Node::new(note.commitment().get_x());
        let root = merkle_path.root(cm_node).inner();
        let auth_path: [(CP::CurveScalarField, bool); TAIGA_COMMITMENT_TREE_DEPTH] =
            merkle_path.get_path().as_slice().try_into().unwrap();
        Self {
            note,
            auth_path,
            root,
        }
    }
}

impl<CP: CircuitParameters> OutputInfo<CP> {
    pub fn new(
        addr_send_closed: UserSendAddress<CP>,
        addr_recv_vp: ValidityPredicateDescription<CP>,
        addr_app_vp: ValidityPredicateDescription<CP>,
        value: u64,
        data: CP::CurveScalarField,
    ) -> Self {
        Self {
            addr_send_closed,
            addr_recv_vp,
            addr_app_vp,
            value,
            data,
        }
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        use rand::Rng;
        let addr_send_closed = UserSendAddress::from_closed(CP::CurveScalarField::random(&mut rng));
        let addr_recv_vp = ValidityPredicateDescription::dummy(&mut rng);
        let addr_app_vp = ValidityPredicateDescription::dummy(&mut rng);
        let value: u64 = rng.gen();
        let data = CP::CurveScalarField::random(rng);
        Self {
            addr_send_closed,
            addr_recv_vp,
            addr_app_vp,
            value,
            data,
        }
    }
}
