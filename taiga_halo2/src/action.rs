use crate::{
    circuit::action_circuit::ActionCircuit,
    merkle_tree::{MerklePath, Node},
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
    input_note: Note,
    input_merkle_path: MerklePath,
    output_note: Note,
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
    pub fn new(
        input_note: Note,
        input_merkle_path: MerklePath,
        output_note: Note,
        rcv: pallas::Scalar,
    ) -> Self {
        Self {
            input_note,
            input_merkle_path,
            output_note,
            rcv,
        }
    }

    pub fn from_proving_info<R: RngCore>(
        input: InputNoteProvingInfo,
        output: OutputNoteProvingInfo,
        mut rng: R,
    ) -> Self {
        let rcv = pallas::Scalar::random(&mut rng);
        Self {
            input_note: input.note,
            input_merkle_path: input.merkle_path,
            output_note: output.note,
            rcv,
        }
    }

    pub fn get_rcv(&self) -> pallas::Scalar {
        self.rcv
    }

    pub fn build(&self) -> (ActionInstance, ActionCircuit) {
        let nf = self.input_note.get_nf().unwrap();
        assert_eq!(
            nf, self.output_note.rho,
            "The nf of input note should be equal to the rho of output note"
        );

        let cm_x = self.output_note.commitment().get_x();
        let anchor = {
            let cm_node = Node::new(self.input_note.commitment().get_x());
            self.input_merkle_path.root(cm_node).inner()
        };

        let cv_net = ValueCommitment::new(&self.input_note, &self.output_note, &self.rcv);
        let action = ActionInstance {
            nf,
            cm_x,
            anchor,
            cv_net,
        };

        let action_circuit = ActionCircuit {
            input_note: self.input_note,
            merkle_path: self.input_merkle_path.get_path().try_into().unwrap(),
            output_note: self.output_note,
            rcv: self.rcv,
        };

        (action, action_circuit)
    }
}

#[cfg(test)]
pub mod tests {
    use super::ActionInfo;
    use crate::note::tests::{random_input_proving_info, random_output_proving_info};
    use rand::RngCore;
    pub fn random_action_info<R: RngCore>(mut rng: R) -> ActionInfo {
        let input_proving_info = random_input_proving_info(&mut rng);
        let output_proving_info =
            random_output_proving_info(&mut rng, input_proving_info.note.get_nf().unwrap());
        ActionInfo::from_proving_info(input_proving_info, output_proving_info, &mut rng)
    }
}
