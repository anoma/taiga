use crate::circuit::circuit_parameters::CircuitParameters;
use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;
use crate::note::Note;
use plonk_core::{
    // prelude::Proof,
    circuit::Circuit,
    // proof_system::{pi::PublicInputs, Prover, Verifier, VerifierKey},
    constraint_system::StandardComposer,
};
// use crate::error::TaigaError;
use crate::circuit::gadgets::merkle_tree::merkle_tree_gadget;
use crate::circuit::integrity::{
    note_commitment_circuit, nullifier_circuit, output_user_address_integrity_circuit,
    spent_user_address_integrity_circuit, token_integrity_circuit,
};
use crate::poseidon::WIDTH_3;
use plonk_hashing::poseidon::constants::PoseidonConstants;

/// Action circuit
#[derive(Debug, Clone)]
pub struct ActionCircuit<CP: CircuitParameters> {
    /// Spent note
    pub spend_note: Note<CP>,
    pub auth_path: [(CP::CurveScalarField, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    /// Output note
    pub output_note: Note<CP>,
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for ActionCircuit<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), plonk_core::prelude::Error> {
        // spent note
        let nf = {
            // check user address
            let nk = self.spend_note.address.send_addr.get_nk().unwrap();
            let nk_var = composer.add_input(nk.inner());
            let address_rcm_var = composer.add_input(self.spend_note.address.rcm);
            let send_vp = self.spend_note.address.send_addr.get_send_vp().unwrap();
            let address_var = spent_user_address_integrity_circuit::<CP>(
                composer,
                &nk_var,
                &address_rcm_var,
                &send_vp.to_bits(),
                &self.spend_note.address.recv_vp.to_bits(),
            )?;

            // check token address
            let token_rcm_var = composer.add_input(self.spend_note.token.rcm);
            let token_var = token_integrity_circuit::<CP>(
                composer,
                &token_rcm_var,
                &self.spend_note.token.token_vp.to_bits(),
            )?;

            // check note commitment
            let value_var = composer.add_input(CP::CurveScalarField::from(self.spend_note.value));
            let data_var = composer.add_input(self.spend_note.data);
            let rho_var = composer.add_input(self.spend_note.rho.inner());
            let note_rcm_var = composer.add_input(self.spend_note.rcm);
            let (cm_var, psi_var) = note_commitment_circuit::<CP>(
                composer,
                &address_var,
                &token_var,
                &value_var,
                &data_var,
                &rho_var,
                &note_rcm_var,
            )?;

            // check merkle tree and publish root
            let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
                PoseidonConstants::generate::<WIDTH_3>();
            let root = merkle_tree_gadget::<
                CP::CurveScalarField,
                CP::InnerCurve,
                PoseidonConstants<CP::CurveScalarField>,
            >(composer, &cm_var, &self.auth_path, &poseidon_param)?;
            composer.public_inputize(&root);

            // check and publish nullifier
            let nullifier_var =
                nullifier_circuit::<CP>(composer, &nk_var, &rho_var, &psi_var, &cm_var)?;
            composer.public_inputize(&nullifier_var);

            // TODO: user send address VP and token VP integrity

            // return old nf
            nullifier_var
        };

        // output note
        {
            // check user address
            let addr_send = self.output_note.address.send_addr.get_closed().unwrap();
            let addr_send_var = composer.add_input(addr_send);
            let address_rcm_var = composer.add_input(self.output_note.address.rcm);
            let address_var = output_user_address_integrity_circuit::<CP>(
                composer,
                &addr_send_var,
                &address_rcm_var,
                &self.output_note.address.recv_vp.to_bits(),
            )?;

            // check token address
            let token_rcm_var = composer.add_input(self.output_note.token.rcm);
            let token_var = token_integrity_circuit::<CP>(
                composer,
                &token_rcm_var,
                &self.output_note.token.token_vp.to_bits(),
            )?;

            // check and publish note commitment
            let value_var = composer.add_input(CP::CurveScalarField::from(self.output_note.value));
            let data_var = composer.add_input(self.output_note.data);
            let note_rcm_var = composer.add_input(self.output_note.rcm);
            let (cm_var, _psi_var) = note_commitment_circuit::<CP>(
                composer,
                &address_var,
                &token_var,
                &value_var,
                &data_var,
                &nf,
                &note_rcm_var,
            )?;

            composer.public_inputize(&cm_var);

            // TODO: user receive address VP and token VP integrity
        }

        Ok(())
    }
    fn padded_circuit_size(&self) -> usize {
        1 << 9
    }
}
