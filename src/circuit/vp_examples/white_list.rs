use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::white_list::white_list_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::merkle_tree::{MerklePath, Node};
use crate::note::Note;
use crate::user::User;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};
use plonk_hashing::poseidon::constants::PoseidonConstants;

// WhiteListValidityPredicate have a custom constraint checking that the received notes come from known users.
pub struct WhiteListValidityPredicate<CP: CircuitParameters> {
    // basic "private" inputs to the VP
    pub input_notes: [Note<CP>; NUM_NOTE],
    pub output_notes: [Note<CP>; NUM_NOTE],
    // custom "private" inputs to the VP
    pub white_list: Vec<User<CP>>,
    pub mk_root: Node<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>,
    pub path: MerklePath<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>,
}

impl<CP> ValidityPredicate<CP> for WhiteListValidityPredicate<CP>
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
        output_note_variables: &[ValidityPredicateOuputNoteVariables],
    ) -> Result<(), Error> {
        let owner_var = output_note_variables[0].recipient_addr;
        let root_var = white_list_gadget::<
            CP::CurveScalarField,
            CP::InnerCurve,
            PoseidonConstants<CP::CurveScalarField>,
            CP,
        >(composer, owner_var, &self.path);
        let expected_var = composer.add_input(self.mk_root.inner());
        composer.assert_equal(expected_var, root_var);
        Ok(())
    }
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for WhiteListValidityPredicate<CP>
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
fn test_white_list_vp_example() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::merkle_tree::MerkleTreeLeafs;
    use crate::poseidon::{FieldHasher, WIDTH_3};
    use ark_std::test_rng;

    type Fr = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use ark_poly_commit::PolynomialCommitment;
    use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
    let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

    // white list is a list of four user addresses, containing `output_notes[0]`'s address.
    let white_list: Vec<User<CP>> = vec![
        User::<CP>::new(&mut rng),
        output_notes[0].user,
        User::<CP>::new(&mut rng),
        User::<CP>::new(&mut rng),
    ];

    let white_list_to_fields: Vec<Fr> = white_list.iter().map(|v| v.address().unwrap()).collect();

    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mk_root = MerkleTreeLeafs::<Fr, PoseidonConstants<Fr>>::new(white_list_to_fields.to_vec())
        .root(&poseidon_hash_param_bls12_377_scalar_arity2);

    let hash_2_3 = PoseidonConstants::generate::<WIDTH_3>()
        .native_hash_two(&white_list_to_fields[2], &white_list_to_fields[3])
        .unwrap();
    let path = MerklePath::from_path(vec![
        (
            Node::<Fr, PoseidonConstants<_>>::new(white_list_to_fields[0]),
            true,
        ),
        (Node::<Fr, PoseidonConstants<_>>::new(hash_2_3), false),
    ]);

    let mut white_list_vp = WhiteListValidityPredicate {
        input_notes,
        output_notes,
        white_list,
        mk_root,
        path,
    };

    // Generate CRS
    let pp = PC::setup(white_list_vp.padded_circuit_size(), None, &mut rng).unwrap();

    // Compile the circuit
    let (pk_p, vk) = white_list_vp.compile::<PC>(&pp).unwrap();

    // Prover
    let (proof, pi) = white_list_vp.gen_proof::<PC>(&pp, pk_p, b"Test").unwrap();

    // Verifier
    let verifier_data = VerifierData::new(vk, pi);
    verify_proof::<Fr, P, PC>(&pp, verifier_data.key, &proof, &verifier_data.pi, b"Test").unwrap();
}
