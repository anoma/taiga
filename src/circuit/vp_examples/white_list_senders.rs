use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::merkle_tree::merkle_tree_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::merkle_tree::{MerklePath, Node};
use crate::note::Note;
use crate::poseidon::WIDTH_3;
use crate::user::User;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};
use plonk_hashing::poseidon::constants::PoseidonConstants;

// WhiteListSendersValidityPredicate have a custom constraint checking that the received notes come from known senders.
pub struct WhiteListSendersValidityPredicate<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    input_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
    // custom "private" inputs to the VP
    white_list_senders: Vec<User>,
    mk_root: Node<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>,
    paths: Vec<MerklePath<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>>,
}

impl ValidityPredicate for WhiteListSendersValidityPredicate
where
    CP: CircuitParameters,
{
    fn get_input_notes(&self) -> &[Note; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn custom_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        _input_note_variables: &[ValidityPredicateInputNoteVariables],
        output_note_variables: &[ValidityPredicateOuputNoteVariables],
    ) -> Result<(), Error> {
        let expected_var = composer.add_input(self.mk_root.inner());
        let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
        for (output_note_variable, path) in output_note_variables.iter().zip(self.paths.clone()) {
            let owner_var = output_note_variable.recipient_addr;
            let root_var = merkle_tree_gadget::<
                CP::CurveScalarField,
                CP::InnerCurve,
                PoseidonConstants<CP::CurveScalarField>,
            >(
                composer,
                &owner_var,
                &path.get_path(),
                &poseidon_hash_param_bls12_377_scalar_arity2,
            )
            .unwrap();
            composer.assert_equal(expected_var, root_var);
        }
        Ok(())
    }
}

impl Circuit<CP::CurveScalarField, CP::InnerCurve> for WhiteListSendersValidityPredicate
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        self.gadget_vp(composer)
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 17
    }
}

#[test]
fn test_white_list_senders_vp_example() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::merkle_tree::MerkleTreeLeafs;
    use crate::poseidon::WIDTH_3;
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    // use ark_poly_commit::PolynomialCommitment;
    // use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::::dummy(&mut rng));

    // white list is a list of user addresses, containing the output notes addresses.
    let white_list_senders: Vec<User> = vec![
        User::::new(&mut rng),
        output_notes[1].user.clone(),
        User::::new(&mut rng),
        User::::new(&mut rng),
        output_notes[3].user.clone(),
        output_notes[2].user.clone(),
        User::::new(&mut rng),
        output_notes[0].user.clone(),
        User::::new(&mut rng),
        User::::new(&mut rng),
        User::::new(&mut rng),
    ];

    let white_list_senders_to_fields: Vec<Fr> = white_list_senders
        .iter()
        .map(|v| v.address().unwrap())
        .collect();

    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mk_root =
        MerkleTreeLeafs::<Fr, PoseidonConstants<Fr>>::new(white_list_senders_to_fields.to_vec())
            .root(&poseidon_hash_param_bls12_377_scalar_arity2);

    let paths: Vec<MerklePath<Fr, PoseidonConstants<Fr>>> = vec![
        MerklePath::build_merkle_path(&white_list_senders_to_fields, 7),
        MerklePath::build_merkle_path(&white_list_senders_to_fields, 1),
        MerklePath::build_merkle_path(&white_list_senders_to_fields, 5),
        MerklePath::build_merkle_path(&white_list_senders_to_fields, 4),
    ];

    let mut white_list_senders_vp = WhiteListSendersValidityPredicate {
        input_notes,
        output_notes,
        white_list_senders,
        mk_root,
        paths,
    };

    let mut composer = StandardComposer::<Fr, P>::new();
    white_list_senders_vp.gadget(&mut composer).unwrap();
    composer.check_circuit_satisfied();
    println!(
        "circuit size of white_list_senders_vp: {}",
        composer.circuit_bound()
    );

    // // Generate CRS
    // let pp = PC::setup(white_list_senders_vp.padded_circuit_size(), None, &mut rng).unwrap();

    // // Compile the circuit
    // let (pk_p, vk) = white_list_senders_vp.compile::<PC>(&pp).unwrap();

    // // Prover
    // let (proof, pi) = white_list_senders_vp
    //     .gen_proof::<PC>(&pp, pk_p, b"Test")
    //     .unwrap();

    // // Verifier
    // let verifier_data = VerifierData::new(vk, pi);
    // verify_proof::<Fr, P, PC>(&pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
