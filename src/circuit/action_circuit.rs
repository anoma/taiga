use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::merkle_tree::merkle_tree_gadget;
use crate::circuit::integrity::{input_note_constraint, output_note_constraint};
use crate::constant::ACTION_CIRCUIT_SIZE;
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
            let input_note_var = input_note_constraint(&self.spend_note, composer)?;
            // check merkle tree and publish root
            let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
                PoseidonConstants::generate::<WIDTH_3>();
            let root = merkle_tree_gadget::<
                CP::CurveScalarField,
                CP::InnerCurve,
                PoseidonConstants<CP::CurveScalarField>,
            >(
                composer,
                &input_note_var.cm,
                &self.auth_path,
                &poseidon_param,
            )?;
            composer.public_inputize(&root);

            // TODO: user send address VP commitment and token VP commitment
            input_note_var.nf
        };

        // output note
        {
            let _output_note_var = output_note_constraint(&self.output_note, &nf, composer)?;

            // TODO: add user receive address VP commitment and token VP commitment

            // TODO: add note encryption
        }

        composer.check_circuit_satisfied();
        println!("circuit size: {}", composer.circuit_bound());

        Ok(())
    }
    fn padded_circuit_size(&self) -> usize {
        ACTION_CIRCUIT_SIZE
    }
}

#[test]
fn action_circuit_test() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use crate::action::*;
    use crate::constant::{
        ACTION_PUBLIC_INPUT_CM_INDEX, ACTION_PUBLIC_INPUT_NF_INDEX, ACTION_PUBLIC_INPUT_ROOT_INDEX,
    };
    use ark_std::test_rng;
    use plonk_core::circuit::{verify_proof, VerifierData};
    use plonk_core::proof_system::pi::PublicInputs;

    let mut rng = test_rng();
    let action_info = ActionInfo::<CP>::dummy(&mut rng);
    let (action, mut action_circuit) = action_info.build(&mut rng).unwrap();

    // Generate CRS
    let pp = CP::get_pc_setup_params(ACTION_CIRCUIT_SIZE);

    // Compile the circuit
    let pk = CP::get_action_pk();
    let vk = CP::get_action_vk();

    // Prover
    let (proof, action_public_input) = action_circuit
        .gen_proof::<PC>(pp, pk.clone(), b"Test")
        .unwrap();

    // Check the public inputs
    let mut expect_public_input = PublicInputs::new(action_circuit.padded_circuit_size());
    expect_public_input.insert(ACTION_PUBLIC_INPUT_NF_INDEX, action.nf.inner());
    expect_public_input.insert(ACTION_PUBLIC_INPUT_ROOT_INDEX, action.root);
    expect_public_input.insert(ACTION_PUBLIC_INPUT_CM_INDEX, action.cm.inner());
    assert_eq!(action_public_input, expect_public_input);
    // Verifier
    let verifier_data = VerifierData::new(vk.clone(), expect_public_input);
    verify_proof::<Fr, P, PC>(pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
