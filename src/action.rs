use crate::circuit::circuit_parameters::CircuitParameters;
use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;
use crate::note::{Note, NoteCommitment};
use crate::nullifier::Nullifier;
use ark_ff::UniformRand;
use rand::RngCore;
// use crate::circuit::action_circuit::ActionCircuit;
use crate::circuit::action_circuit::ActionCircuit;
use crate::error::TaigaError;
use crate::token::TokenAddress;
use crate::user_address::{UserAddress, UserSendAddress};
use crate::validity_predicate::MockHashVP;

/// The action result used in transaction.
#[derive(Copy, Debug, Clone)]
pub struct Action<CP: CircuitParameters> {
    /// The nullifier of spend note.
    nf: Nullifier<CP>,
    /// The commitment of output.
    cm: NoteCommitment<CP>,
    // TODO: The EncryptedNote.
    // encrypted_note,
}

/// The information to build Action and ActionCircuit.
#[derive(Copy, Debug, Clone)]
pub struct ActionInfo<CP: CircuitParameters> {
    spend: SpendInfo<CP>,
    output: OutputInfo<CP>,
}

#[derive(Copy, Debug, Clone)]
pub struct SpendInfo<CP: CircuitParameters> {
    note: Note<CP>,
    auth_path: [(CP::CurveScalarField, bool); TAIGA_COMMITMENT_TREE_DEPTH],
}

#[derive(Copy, Debug, Clone)]
pub struct OutputInfo<CP: CircuitParameters> {
    addr_send_closed: CP::CurveScalarField,
    addr_recv_vp: MockHashVP<CP>,
    addr_token_vp: MockHashVP<CP>,
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
        let nk = self.spend.note.address.send_addr.get_nk().unwrap();
        let nf = Nullifier::<CP>::derive_native(
            &nk,
            &self.spend.note.rho,
            &self.spend.note.psi,
            &spend_cm,
        );
        let action = Action::<CP> { nf, cm: spend_cm };

        let addr_rcm = CP::CurveScalarField::rand(rng);
        let address = UserAddress::<CP> {
            send_addr: UserSendAddress::from_closed(self.output.addr_send_closed),
            rcm: addr_rcm,
            recv_vp: self.output.addr_recv_vp,
        };
        let token_rcm = CP::CurveScalarField::rand(rng);
        let token = TokenAddress::<CP> {
            rcm: token_rcm,
            token_vp: self.output.addr_token_vp,
        };

        let note_rcm = CP::CurveScalarField::rand(rng);
        let output_note = Note::new(
            address,
            token,
            self.output.value,
            nf.clone(),
            self.output.data,
            note_rcm,
        );
        let action_circuit = ActionCircuit::<CP> {
            spend_note: self.spend.note,
            auth_path: self.spend.auth_path,
            output_note,
        };

        Ok((action, action_circuit))
    }
}
