use crate::merkle_tree::Node;
use crate::note::Note;
use crate::poseidon::WIDTH_3;
use crate::{circuit::circuit_parameters::CircuitParameters, merkle_tree::MerklePath};
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use plonk_core::prelude::StandardComposer;
use plonk_hashing::poseidon::constants::PoseidonConstants;

use super::bad_hash_to_curve::bad_hash_to_curve_gadget;
use super::merkle_tree::merkle_tree_gadget;

pub fn white_list_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    private_note: Note<CP>,
    private_white_list_merkle_tree_path: MerklePath<
        <CP as CircuitParameters>::CurveScalarField,
        PoseidonConstants<<CP as CircuitParameters>::CurveScalarField>,
    >,
    private_white_list_merkle_tree_root: Node<
        CP::CurveScalarField,
        PoseidonConstants<CP::CurveScalarField>,
    >, // todo: can be replaced with the white list directly?
    public_note_commitment: TEGroupAffine<CP::InnerCurve>,
) {
    // opening of the note_commitment
    let crh_point = bad_hash_to_curve_gadget::<CP>(
        composer,
        &vec![private_note.owner_address, private_note.token_address],
        &vec![],
    );
    composer.assert_equal_public_point(crh_point, public_note_commitment);

    let commitment = composer.add_input(private_note.owner_address);
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let root_var = merkle_tree_gadget::<
        CP::CurveScalarField,
        CP::InnerCurve,
        PoseidonConstants<CP::CurveScalarField>,
    >(
        composer,
        &commitment,
        &private_white_list_merkle_tree_path.get_path(),
        &poseidon_hash_param_bls12_377_scalar_arity2,
    )
    .unwrap();

    let expected_var = composer.add_input(private_white_list_merkle_tree_root.inner());
    composer.assert_equal(expected_var, root_var);
}

#[test]
fn test_white_list_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::note::Note;
    use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve};
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;

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
    let merkle_path = MerklePath::<
        <CP as CircuitParameters>::CurveScalarField,
        PoseidonConstants<<CP as CircuitParameters>::CurveScalarField>,
    >::dummy(&mut rng, 2);

    let cur_leaf = Node::new(note.owner_address);
    // Get the white list tree root.
    let expected_root = merkle_path
        .root(cur_leaf, &poseidon_hash_param_bls12_377_scalar_arity2)
        .unwrap();

    let mut composer = StandardComposer::<
        <CP as CircuitParameters>::CurveScalarField,
        <CP as CircuitParameters>::InnerCurve,
    >::new();
    white_list_gadget::<CP>(&mut composer, note, merkle_path, expected_root, note_com);
    composer.check_circuit_satisfied();
}
