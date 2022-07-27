use crate::circuit::action_circuit::ActionCircuit;
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::error::TaigaError;
use crate::merkle_tree::{MerklePath, Node, TAIGA_COMMITMENT_TREE_DEPTH};
use crate::note::{Note, NoteCommitment};
use crate::nullifier::Nullifier;
use crate::poseidon::FieldHasher;
use crate::token::Token;
use crate::user::{User, UserSendAddress};
use crate::vp_description::ValidityPredicateDescription;
use ark_ff::UniformRand;
use rand::RngCore;

/// The action result used in transaction.
#[derive(Copy, Debug, Clone)]
pub struct Action<CP: CircuitParameters> {
    /// The root of the note commitment Merkle tree.
    pub root: CP::CurveScalarField,
    /// The nullifier of the spend note.
    pub nf: Nullifier<CP>,
    /// The commitment of the output note.
    pub cm: NoteCommitment<CP>,
    // TODO: The EncryptedNote.
    // encrypted_note,
}

/// The information to build Action and ActionCircuit.
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
    addr_token_vp: ValidityPredicateDescription<CP>,
    value: u64,
    data: CP::CurveScalarField,
}

impl<CP: CircuitParameters> ActionInfo<CP> {
    pub fn new(spend: SpendInfo<CP>, output: OutputInfo<CP>) -> Self {
        Self { spend, output }
    }

    pub fn build(
        self,
        rng: &mut impl RngCore,
    ) -> Result<(Action<CP>, ActionCircuit<CP>), TaigaError> {
        let spend_cm = self.spend.note.commitment()?;
        let nk = self.spend.note.user.send_com.get_nk().unwrap();
        let nf = Nullifier::<CP>::derive_native(
            &nk,
            &self.spend.note.rho,
            &self.spend.note.psi,
            &spend_cm,
        );

        let user = User::<CP> {
            send_com: self.output.addr_send_closed,
            recv_vp: self.output.addr_recv_vp,
        };
        let token = Token::<CP> {
            token_vp: self.output.addr_token_vp,
        };

        let note_rcm = CP::CurveScalarField::rand(rng);
        let output_note = Note::new(
            user,
            token,
            self.output.value,
            nf,
            self.output.data,
            note_rcm,
        );

        let output_cm = output_note.commitment()?;
        let action = Action::<CP> {
            nf,
            cm: output_cm,
            root: self.spend.root,
        };

        let action_circuit = ActionCircuit::<CP> {
            spend_note: self.spend.note,
            auth_path: self.spend.auth_path,
            output_note,
        };

        Ok((action, action_circuit))
    }
}

impl<CP: CircuitParameters> SpendInfo<CP> {
    pub fn new<BH>(
        note: Note<CP>,
        merkle_path: MerklePath<CP::CurveScalarField, BH>,
        hasher: &BH,
    ) -> Self
    where
        BH: FieldHasher<CP::CurveScalarField>,
    {
        let cm_node = Node::<CP::CurveScalarField, BH>::new(note.commitment().unwrap().inner());
        let root = merkle_path.root(cm_node, hasher).unwrap().inner();
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
        addr_token_vp: ValidityPredicateDescription<CP>,
        value: u64,
        data: CP::CurveScalarField,
    ) -> Self {
        Self {
            addr_send_closed,
            addr_recv_vp,
            addr_token_vp,
            value,
            data,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        use rand::Rng;
        let addr_send_closed = UserSendAddress::<CP>::from_closed(CP::CurveScalarField::rand(rng));
        let addr_recv_vp = ValidityPredicateDescription::<CP>::dummy(rng);
        let addr_token_vp = ValidityPredicateDescription::<CP>::dummy(rng);
        let value: u64 = rng.gen();
        let data = CP::CurveScalarField::rand(rng);
        Self {
            addr_send_closed,
            addr_recv_vp,
            addr_token_vp,
            value,
            data,
        }
    }
}
