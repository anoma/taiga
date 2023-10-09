use crate::{
    circuit::action_circuit::ActionCircuit,
    constant::{PRF_EXPAND_INPUT_VP_CM_R, PRF_EXPAND_OUTPUT_VP_CM_R},
    merkle_tree::{Anchor, MerklePath},
    note::{InputNoteProvingInfo, Note, NoteCommitment, OutputNoteProvingInfo, RandomSeed},
    nullifier::Nullifier,
    value_commitment::ValueCommitment,
    vp_commitment::ValidityPredicateCommitment,
};
use pasta_curves::pallas;
use rand::RngCore;

#[cfg(feature = "nif")]
use rustler::NifStruct;

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// The public inputs of action proof.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Taiga.Action.PublicInputs")]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionPublicInputs {
    /// The root of the note commitment Merkle tree.
    pub anchor: Anchor,
    /// The nullifier of input note.
    pub nf: Nullifier,
    /// The commitment to the output note.
    pub cm: NoteCommitment,
    /// net value commitment
    pub cv_net: ValueCommitment,
    /// The commitment to input note application(static) vp
    pub input_vp_commitment: ValidityPredicateCommitment,
    /// The commitment to output note application(static) vp
    pub output_vp_commitment: ValidityPredicateCommitment,
}

/// The information to build ActionPublicInputs and ActionCircuit.
#[derive(Clone)]
pub struct ActionInfo {
    input_note: Note,
    input_merkle_path: MerklePath,
    input_anchor: Anchor,
    output_note: Note,
    // rseed is to generate the randomness of the value commitment and vp commitments
    rseed: RandomSeed,
}

impl ActionPublicInputs {
    pub fn to_instance(&self) -> Vec<pallas::Base> {
        let input_vp_commitment = self.input_vp_commitment.to_public_inputs();
        let output_vp_commitment = self.output_vp_commitment.to_public_inputs();
        vec![
            self.nf.inner(),
            self.anchor.inner(),
            self.cm.inner(),
            self.cv_net.get_x(),
            self.cv_net.get_y(),
            input_vp_commitment[0],
            input_vp_commitment[1],
            output_vp_commitment[0],
            output_vp_commitment[1],
        ]
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for ActionPublicInputs {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.anchor.to_bytes())?;
        writer.write_all(&self.nf.to_bytes())?;
        writer.write_all(&self.cm.to_bytes())?;
        writer.write_all(&self.cv_net.to_bytes())?;
        writer.write_all(&self.input_vp_commitment.to_bytes())?;
        writer.write_all(&self.output_vp_commitment.to_bytes())?;
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for ActionPublicInputs {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        use std::io;
        let anchor_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let anchor = Option::from(Anchor::from_bytes(anchor_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "anchor not in field"))?;
        let nf_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let nf = Option::from(Nullifier::from_bytes(nf_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nf not in field"))?;
        let cm_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let cm = Option::from(NoteCommitment::from_bytes(cm_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cm not in field"))?;
        let cv_net_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let cv_net = Option::from(ValueCommitment::from_bytes(cv_net_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cv_net not in field"))?;
        let input_vp_commitment_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let input_vp_commitment =
            ValidityPredicateCommitment::from_bytes(input_vp_commitment_bytes);
        let output_vp_commitment_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let output_vp_commitment =
            ValidityPredicateCommitment::from_bytes(output_vp_commitment_bytes);

        Ok(ActionPublicInputs {
            anchor,
            nf,
            cm,
            cv_net,
            input_vp_commitment,
            output_vp_commitment,
        })
    }
}

impl ActionInfo {
    pub fn new(
        input_note: Note,
        input_merkle_path: MerklePath,
        input_anchor: Anchor,
        output_note: Note,
        rseed: RandomSeed,
    ) -> Self {
        Self {
            input_note,
            input_merkle_path,
            input_anchor,
            output_note,
            rseed,
        }
    }

    pub fn from_proving_info<R: RngCore>(
        input: InputNoteProvingInfo,
        output: OutputNoteProvingInfo,
        mut rng: R,
    ) -> Self {
        let rseed = RandomSeed::random(&mut rng);
        Self {
            input_note: input.note,
            input_merkle_path: input.merkle_path,
            input_anchor: input.anchor,
            output_note: output.note,
            rseed,
        }
    }

    // Get the randomness of value commitment
    pub fn get_rcv(&self) -> pallas::Scalar {
        self.rseed.get_rcv()
    }

    // Get the randomness of input note application vp commitment
    pub fn get_input_vp_com_r(&self) -> pallas::Base {
        self.rseed.get_vp_cm_r(PRF_EXPAND_INPUT_VP_CM_R)
    }

    // Get the randomness of output note application vp commitment
    pub fn get_output_vp_com_r(&self) -> pallas::Base {
        self.rseed.get_vp_cm_r(PRF_EXPAND_OUTPUT_VP_CM_R)
    }

    pub fn build(&self) -> (ActionPublicInputs, ActionCircuit) {
        let nf = self.input_note.get_nf().unwrap();
        assert_eq!(
            nf, self.output_note.rho,
            "The nf of input note should be equal to the rho of output note"
        );

        let cm = self.output_note.commitment();

        let rcv = self.get_rcv();
        let cv_net = ValueCommitment::new(&self.input_note, &self.output_note, &rcv);

        let input_vp_cm_r = self.get_input_vp_com_r();
        let input_vp_commitment =
            ValidityPredicateCommitment::commit(&self.input_note.get_app_vk(), &input_vp_cm_r);

        let output_vp_cm_r = self.get_output_vp_com_r();
        let output_vp_commitment =
            ValidityPredicateCommitment::commit(&self.output_note.get_app_vk(), &output_vp_cm_r);

        let action = ActionPublicInputs {
            nf,
            cm,
            anchor: self.input_anchor,
            cv_net,
            input_vp_commitment,
            output_vp_commitment,
        };

        let action_circuit = ActionCircuit {
            input_note: self.input_note,
            merkle_path: self.input_merkle_path.get_path().try_into().unwrap(),
            output_note: self.output_note,
            rcv,
            input_vp_cm_r,
            output_vp_cm_r,
        };

        (action, action_circuit)
    }
}

#[cfg(test)]
pub mod tests {
    use super::ActionInfo;
    use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
    use crate::merkle_tree::{MerklePath, Node};
    use crate::note::tests::{random_input_note, random_output_note};
    use crate::note::RandomSeed;
    use rand::RngCore;

    pub fn random_action_info<R: RngCore>(mut rng: R) -> ActionInfo {
        let input_note = random_input_note(&mut rng);
        let output_note = random_output_note(&mut rng, input_note.get_nf().unwrap());
        let input_merkle_path = MerklePath::random(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
        let input_anchor = {
            let cm_note = Node::from(&input_note);
            input_merkle_path.root(cm_note)
        };
        let rseed = RandomSeed::random(&mut rng);
        ActionInfo::new(
            input_note,
            input_merkle_path,
            input_anchor,
            output_note,
            rseed,
        )
    }
}
