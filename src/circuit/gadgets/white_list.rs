use crate::merkle_tree::Node;
use crate::poseidon::WIDTH_3;
use crate::{circuit::circuit_parameters::CircuitParameters, merkle_tree::MerklePath};
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine};
use plonk_core::prelude::StandardComposer;
use plonk_hashing::poseidon::constants::PoseidonConstants;

use super::bad_hash_to_curve::bad_hash_to_curve_gadget;
use super::merkle_tree::merkle_tree_gadget;

pub fn white_list_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    private_inputs: &Vec<CP::CurveScalarField>,
    public_inputs: &Vec<CP::CurveScalarField>,
) {
    // private inputs
    let owner_address = private_inputs[0];
    let token_address = private_inputs[1];
    let _path = &private_inputs[2..]; // todo
    // public inputs
    let com_x = public_inputs[0];
    let com_y = public_inputs[1];
    let note_commitment: TEGroupAffine<CP::InnerCurve> = TEGroupAffine::new(com_x, com_y);

    // opening of the note_commitment
    let crh_point =
        bad_hash_to_curve_gadget::<CP>(composer, &vec![owner_address, token_address], &vec![]);
    composer.assert_equal_public_point(crh_point, note_commitment);

    // white list (as a merkle tree) membership
    let merkle_path = MerklePath::from_path(vec![
        (
            Node::<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>::new(
                private_inputs[0],
            ),
            true,
        ),
        (
            Node::<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>::new(
                private_inputs[1],
            ),
            false,
        ),
        // etc.
    ]);
    let cur_leaf = Node::<CP::CurveScalarField, PoseidonConstants<CP::CurveScalarField>>::new(
        private_inputs[0],
    ); // node owner address
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let expected = merkle_path
        .root(
            cur_leaf.clone(),
            &poseidon_hash_param_bls12_377_scalar_arity2,
        )
        .unwrap();

    let commitment = composer.add_input(owner_address);
    let root = merkle_tree_gadget::<
        CP::CurveScalarField,
        CP::InnerCurve,
        PoseidonConstants<CP::CurveScalarField>,
    >(
        composer,
        &commitment,
        &merkle_path.get_path(),
        &poseidon_hash_param_bls12_377_scalar_arity2,
    )
    .unwrap();

    let expected_var = composer.add_input(expected.inner());
    composer.assert_equal(expected_var, root);
}

#[test]
fn test_white_list_gadget() {
    use crate::circuit::circuit_parameters::{
        CircuitParameters, PairingCircuitParameters as CP,
    };
    use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;
    use crate::note::Note;

    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();

    let mut rng = rand::thread_rng();

    // a note owned by one of the white list user
    let note = Note::<CP>::new(
        <CP as CircuitParameters>::CurveScalarField::rand(&mut rng),
        <CP as CircuitParameters>::CurveScalarField::rand(&mut rng),
        12,
        TEGroupAffine::<<CP as CircuitParameters>::InnerCurve>::prime_subgroup_generator(),
        <CP as CircuitParameters>::InnerCurveScalarField::rand(&mut rng),
        &mut rng,
    );
    let note_com = note.commitment();

    // Generate a dummy white list tree path with depth 2.
    let merkle_path = MerklePath::<<CP as CircuitParameters>::CurveScalarField, PoseidonConstants<<CP as CircuitParameters>::CurveScalarField>>::dummy(&mut rng, 2);

    let cur_leaf = Node::new(note.owner_address);
    // Get the white list tree root.
    let expected_root = merkle_path
    .root(
        cur_leaf,
        &poseidon_hash_param_bls12_377_scalar_arity2,
    )
    .unwrap();

    let todo = <CP as CircuitParameters>::CurveScalarField::from(2u64); // todo merkle tree work here

    // let merkle_path = MerklePath::from_path(vec![
    //     (Node::<<CP as CircuitParameters>::CurveScalarField, PoseidonConstants<<CP as CircuitParameters>::CurveScalarField>>::new(white_list[0]),true),
    //     (Node::<<CP as CircuitParameters>::CurveScalarField, PoseidonConstants<<CP as CircuitParameters>::CurveScalarField>>::new(white_list[1]),true),
    //     (Node::<<CP as CircuitParameters>::CurveScalarField, PoseidonConstants<<CP as CircuitParameters>::CurveScalarField>>::new(white_list[2]),true),
    //     (Node::<<CP as CircuitParameters>::CurveScalarField, PoseidonConstants<<CP as CircuitParameters>::CurveScalarField>>::new(white_list[3]),true),
    // ]);

    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();
    white_list_gadget::<CP>(
        &mut composer,
        &vec![note.owner_address, note.token_address, todo],
        &vec![note_com.x, note_com.y],
    );
    // composer.check_circuit_satisfied();
}
