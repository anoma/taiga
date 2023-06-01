use crate::{
    circuit::action_circuit::ActionCircuit,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteProvingInfo, Note, NoteCommitment, OutputNoteProvingInfo},
    nullifier::Nullifier,
    value_commitment::ValueCommitment,
};
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::RngCore;

/// The action result used in transaction.
#[derive(Copy, Debug, Clone)]
pub struct ActionInstance {
    /// The root of the note commitment Merkle tree.
    pub anchor: pallas::Base,
    /// The nullifier of input note.
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
    input: InputNoteProvingInfo,
    output: OutputNoteProvingInfo,
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
    pub fn new<R: RngCore>(
        input: InputNoteProvingInfo,
        output: OutputNoteProvingInfo,
        mut rng: R,
    ) -> Self {
        let rcv = pallas::Scalar::random(&mut rng);
        Self { input, output, rcv }
    }

    pub fn get_rcv(&self) -> pallas::Scalar {
        self.rcv
    }

    pub fn dummy<R: RngCore>(mut rng: R) -> Self {
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        let input_note = Note::dummy(&mut rng);
        let output_proving_info =
            OutputNoteProvingInfo::dummy(&mut rng, input_note.get_nf().unwrap());
        let merkle_path = MerklePath::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let app_vp_proving_info = Box::new(TrivialValidityPredicateCircuit::dummy(&mut rng));
        let app_vp_proving_info_dynamic = vec![];
        let input_proving_info = InputNoteProvingInfo::new(
            input_note,
            merkle_path,
            app_vp_proving_info,
            app_vp_proving_info_dynamic,
        );

        ActionInfo::new(input_proving_info, output_proving_info, &mut rng)
    }

    pub fn build(self) -> (ActionInstance, ActionCircuit) {
        let nf = self.input.note.get_nf().unwrap();
        assert_eq!(
            nf, self.output.note.rho,
            "The nf of input note should be equal to the rho of output note"
        );

        let output_cm = self.output.note.commitment();

        let cv_net = ValueCommitment::new(&self.input.note, &self.output.note, &self.rcv);
        let action = ActionInstance {
            nf,
            cm: output_cm,
            anchor: self.input.root,
            cv_net,
        };

        let action_circuit = ActionCircuit {
            input_note: self.input.note,
            auth_path: self.input.auth_path,
            output_note: self.output.note,
            rcv: self.rcv,
        };

        (action, action_circuit)
    }
}
