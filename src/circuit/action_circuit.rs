use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::merkle_tree::merkle_tree_gadget;
use crate::circuit::integrity::{
    note_commitment_circuit, nullifier_circuit, output_user_address_integrity_circuit,
    spent_user_address_integrity_circuit, token_integrity_circuit,
};
use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;
use crate::note::Note;
use crate::poseidon::WIDTH_3;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer};
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

            // TODO: user send address VP commitment and token VP commitment

            // check nullifier and return it
            nullifier_circuit::<CP>(composer, &nk_var, &rho_var, &psi_var, &cm_var)?
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

            // TODO: add user receive address VP commitment and token VP commitment

            // TODO: add note encryption
        }

        Ok(())
    }
    fn padded_circuit_size(&self) -> usize {
        1 << 16
    }
}

#[test]
fn action_circuit_test() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use crate::action::*;
    use crate::merkle_tree::MerklePath;
    use crate::poseidon::POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::test_rng;
    use plonk_core::circuit::{verify_proof, VerifierData};
    use plonk_core::proof_system::pi::PublicInputs;

    let mut rng = test_rng();
    let spend_note = Note::<CP>::dummy(&mut rng);
    let merkle_path =
        MerklePath::<Fr, PoseidonConstants<Fr>>::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);
    let spend_info = SpendInfo::<CP>::new(
        spend_note,
        merkle_path,
        &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
    );

    let output_info = OutputInfo::<CP>::dummy(&mut rng);

    let action_info = ActionInfo::<CP>::new(spend_info, output_info);
    let (action, mut action_circuit) = action_info.build(&mut rng).unwrap();

    // Generate CRS
    let pp = PC::setup(1 << 16, None, &mut rng).unwrap();

    // Compile the circuit
    let (pk_p, vk) = action_circuit.compile::<PC>(&pp).unwrap();

    // Prover
    let (proof, pi) = action_circuit.gen_proof::<PC>(&pp, pk_p, b"Test").unwrap();

    // Check the public inputs
    let mut expect_pi = PublicInputs::new(1 << 16);
    expect_pi.insert(24336, action.root);
    expect_pi.insert(25814, action.nf.inner());
    expect_pi.insert(33918, action.cm.inner());
    assert_eq!(pi, expect_pi);
    // Verifier
    let verifier_data = VerifierData::new(vk, expect_pi);
    verify_proof::<Fr, P, PC>(&pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
