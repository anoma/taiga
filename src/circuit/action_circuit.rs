use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::merkle_tree::merkle_tree_gadget;
use crate::circuit::integrity::{input_note_constraint, output_note_constraint};
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
        1 << 15
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
    let pp = PC::setup(action_circuit.padded_circuit_size(), None, &mut rng).unwrap();

    // Compile the circuit
    let (pk_p, vk) = action_circuit.compile::<PC>(&pp).unwrap();

    // Prover
    let (proof, pi) = action_circuit.gen_proof::<PC>(&pp, pk_p, b"Test").unwrap();

    // Check the public inputs
    let mut expect_pi = PublicInputs::new(action_circuit.padded_circuit_size());
    expect_pi.insert(24337, action.root);
    expect_pi.insert(10352, action.nf.inner());
    expect_pi.insert(30964, action.cm.inner());
    assert_eq!(pi, expect_pi);
    // Verifier
    let verifier_data = VerifierData::new(vk, expect_pi);
    verify_proof::<Fr, P, PC>(&pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
