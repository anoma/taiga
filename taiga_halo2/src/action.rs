use crate::{
    circuit::action_circuit::ActionCircuit,
    constant::TAIGA_COMMITMENT_TREE_DEPTH,
    merkle_tree::MerklePath,
    note::{InputNoteProvingInfo, Note, OutputNoteProvingInfo},
    nullifier::Nullifier,
    value_commitment::ValueCommitment,
};
use borsh::{BorshDeserialize, BorshSerialize};
use ff::PrimeField;
use halo2_proofs::arithmetic::Field;
use pasta_curves::pallas;
use rand::RngCore;
use std::io;

/// The action result used in transaction.
#[derive(Copy, Debug, Clone)]
pub struct ActionInstance {
    /// The root of the note commitment Merkle tree.
    pub anchor: pallas::Base,
    /// The nullifier of input note.
    pub nf: Nullifier,
    /// The commitment of the output note.
    pub cm_x: pallas::Base,
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
            self.cm_x,
            self.cv_net.get_x(),
            self.cv_net.get_y(),
        ]
    }
}

impl BorshSerialize for ActionInstance {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        writer.write_all(&self.anchor.to_repr())?;
        writer.write_all(&self.nf.to_bytes())?;
        writer.write_all(&self.cm_x.to_repr())?;
        writer.write_all(&self.cv_net.to_bytes())?;
        Ok(())
    }
}

impl BorshDeserialize for ActionInstance {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let anchor_bytes = <[u8; 32]>::deserialize(buf)?;
        let anchor = Option::from(pallas::Base::from_repr(anchor_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "anchor not in field"))?;
        let nf_bytes = <[u8; 32]>::deserialize(buf)?;
        let nf = Option::from(Nullifier::from_bytes(nf_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nf not in field"))?;
        let cm_x_bytes = <[u8; 32]>::deserialize(buf)?;
        let cm_x = Option::from(pallas::Base::from_repr(cm_x_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cm_x not in field"))?;
        let cv_net_bytes = <[u8; 32]>::deserialize(buf)?;
        let cv_net = Option::from(ValueCommitment::from_bytes(cv_net_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cv_net not in field"))?;

        Ok(ActionInstance {
            anchor,
            nf,
            cm_x,
            cv_net,
        })
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

        let cm_x = self.output.note.commitment().get_x();

        let cv_net = ValueCommitment::new(&self.input.note, &self.output.note, &self.rcv);
        let action = ActionInstance {
            nf,
            cm_x,
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
