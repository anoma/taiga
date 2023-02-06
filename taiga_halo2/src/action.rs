use crate::{
    circuit::action_circuit::ActionCircuit,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{Note, NoteCommitment, OutputNoteInfo, SpendNoteInfo},
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
    rcv: pallas::Scalar,
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
    pub fn new<R: RngCore>(spend: SpendNoteInfo, output: OutputNoteInfo, mut rng: R) -> Self {
        let rcv = pallas::Scalar::random(&mut rng);
        Self { spend, output, rcv }
    }

    pub fn get_rcv(&self) -> pallas::Scalar {
        self.rcv
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        let spend_note = Note::dummy(&mut rng);
        let output_info = OutputNoteInfo::dummy(&mut rng, spend_note.get_nf().unwrap());
        let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let app_vp_proving_info = Box::new(TrivialValidityPredicateCircuit::dummy(&mut rng));
        let app_vp_proving_info_dynamic = vec![];
        let spend_info = SpendNoteInfo::new(
            spend_note,
            merkle_path,
            app_vp_proving_info,
            app_vp_proving_info_dynamic,
        );

        ActionInfo::new(spend_info, output_info, &mut rng)
    }

    pub fn build(self) -> (ActionInstance, ActionCircuit) {
        let nf = self.spend.note.get_nf().unwrap();
        assert_eq!(
            nf, self.output.note.rho,
            "The nf of spend note should be equal to the rho of output note"
        );

        let output_cm = self.output.note.commitment();

        let cv_net = ValueCommitment::new(&self.spend.note, &self.output.note, &self.rcv);
        let action = ActionInstance {
            nf,
            cm: output_cm,
            anchor: self.spend.root,
            cv_net,
        };

        let action_circuit = ActionCircuit {
            spend_note: self.spend.note,
            auth_path: self.spend.auth_path,
            output_note: self.output.note,
            rcv: self.rcv,
        };

        (action, action_circuit)
    }
}
