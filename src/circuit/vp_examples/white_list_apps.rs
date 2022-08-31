use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::merkle_tree::merkle_tree_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOutputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::merkle_tree::{MerklePath, Node};
use crate::note::Note;
use crate::poseidon::WIDTH_3;
use crate::app::App;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};
use plonk_hashing::poseidon::constants::PoseidonConstants;

// WhiteListAppsValidityPredicate have a custom constraint checking that the received notes come from known senders.
pub struct WhiteListAppsValidityPredicate<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
    // custom "private" inputs to the VP
    white_list_apps: Vec<App<CP>>,
    mk_root: Node<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>,
    paths: Vec<MerklePath<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>>,
}

impl<CP> ValidityPredicate<CP> for WhiteListAppsValidityPredicate<CP>
where
    CP: CircuitParameters,
{
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.output_notes
    }

    fn custom_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        _input_note_variables: &[ValidityPredicateInputNoteVariables],
        output_note_variables: &[ValidityPredicateOutputNoteVariables],
    ) -> Result<(), Error> {
        let expected_var = composer.add_input(self.mk_root.inner());
        let poseidon_hash_param_bls12_381_new_scalar_arity2 =
            PoseidonConstants::generate::<WIDTH_3>();
        for (output_note_variable, path) in output_note_variables.iter().zip(self.paths.clone()) {
            let app_var = output_note_variable.app_addr;
            let root_var = merkle_tree_gadget::<
                CP::CurveScalarField,
                CP::InnerCurve,
                PoseidonConstants<CP::CurveScalarField>,
            >(
                composer,
                &app_var,
                &path.get_path(),
                &poseidon_hash_param_bls12_381_new_scalar_arity2,
            )
            .unwrap();
            composer.assert_equal(expected_var, root_var);
        }
        Ok(())
    }
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for WhiteListAppsValidityPredicate<CP>
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

#[ignore]
#[test]
fn test_white_list_apps_vp_example() {
    use plonk_core::circuit::{verify_proof, VerifierData};

    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::merkle_tree::MerkleTreeLeafs;
    use crate::poseidon::WIDTH_3;
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    // white list is a list of app addresses, containing the output note app addresses.
    let white_list_apps: Vec<App<CP>> = vec![
        App::<CP>::dummy(&mut rng),
        output_notes[1].app.clone(),
        App::<CP>::dummy(&mut rng),
        App::<CP>::dummy(&mut rng),
        output_notes[3].app.clone(),
        output_notes[2].app.clone(),
        App::<CP>::dummy(&mut rng),
        output_notes[0].app.clone(),
        App::<CP>::dummy(&mut rng),
    ];

    let white_list_apps_to_fields: Vec<Fr> = white_list_apps
        .iter()
        .map(|v| v.address().unwrap())
        .collect();

    let poseidon_hash_param_bls12_381_new_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mk_root =
        MerkleTreeLeafs::<Fr, PoseidonConstants<Fr>>::new(white_list_apps_to_fields.to_vec())
            .root(&poseidon_hash_param_bls12_381_new_scalar_arity2);

    let paths: Vec<MerklePath<Fr, PoseidonConstants<Fr>>> = vec![
        MerklePath::build_merkle_path(&white_list_apps_to_fields, 7),
        MerklePath::build_merkle_path(&white_list_apps_to_fields, 1),
        MerklePath::build_merkle_path(&white_list_apps_to_fields, 5),
        MerklePath::build_merkle_path(&white_list_apps_to_fields, 4),
    ];

    let mut white_list_apps_vp = WhiteListAppsValidityPredicate {
        input_notes,
        output_notes,
        white_list_apps,
        mk_root,
        paths,
    };
    let mut composer = StandardComposer::<Fr, P>::new();
    white_list_apps_vp.gadget(&mut composer).unwrap();
    composer.check_circuit_satisfied();
    println!(
        "circuit size of white_list_apps_vp: {}",
        composer.circuit_bound()
    );

    // Generate CRS
    let pp = CP::get_pc_setup_params(white_list_apps_vp.padded_circuit_size());

    // Compile the circuit
    let (pk, vk) = white_list_apps_vp.compile::<PC>(pp).unwrap();

    // Prover
    let (proof, public_input) = white_list_apps_vp
        .gen_proof::<PC>(pp, pk, b"Test")
        .unwrap();

    // Verifier
    let verifier_data = VerifierData::new(vk, public_input);
    verify_proof::<Fr, P, PC>(pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
