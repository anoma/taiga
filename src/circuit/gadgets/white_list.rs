use crate::circuit::circuit_parameters::CircuitParameters;
use crate::merkle_tree::MerklePath;
use crate::merkle_tree::MerkleTreeLeafs;
use crate::note::Note;
use crate::poseidon::WIDTH_3;
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine, TEModelParameters};
use ark_ff::PrimeField;
use plonk_core::prelude::StandardComposer;
use plonk_hashing::poseidon::constants::PoseidonConstants;

use super::bad_hash_to_curve::bad_hash_to_curve_gadget;
use super::hash::BinaryHasherGadget;
use super::merkle_tree::merkle_tree_gadget;

pub fn white_list_gadget<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    BHG: BinaryHasherGadget<F, P>,
    CP: CircuitParameters<CurveScalarField = F, InnerCurve = P>,
>(
    composer: &mut StandardComposer<F, P>,
    private_note: Note<CP>,
    private_white_list_merkle_tree_path: MerklePath<F, PoseidonConstants<F>>,
    private_white_list_addresses: Vec<F>,
    public_note_commitment: TEGroupAffine<P>,
) {
    // opening of the note_commitment
    let crh_point = bad_hash_to_curve_gadget::<F, P>(
        composer,
        &vec![
            private_note.owner_address,
            private_note.token_address,
            F::from(private_note.value),
            F::from(private_note.data),
        ],
    );
    composer.assert_equal_public_point(crh_point, public_note_commitment);

    let commitment = composer.add_input(private_note.owner_address);
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let root_var = merkle_tree_gadget::<F, P, PoseidonConstants<F>>(
        composer,
        &commitment,
        &private_white_list_merkle_tree_path.get_path(),
        &poseidon_hash_param_bls12_377_scalar_arity2,
    )
    .unwrap();

    let mk_root = MerkleTreeLeafs::<F, PoseidonConstants<F>>::new(private_white_list_addresses)
        .root(&poseidon_hash_param_bls12_377_scalar_arity2);
    let expected_var = composer.add_input(mk_root.inner());
    composer.assert_equal(expected_var, root_var);
}

#[test]
fn test_white_list_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::merkle_tree::Node;
    use crate::note::Note;
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;
    use plonk_hashing::poseidon::constants::PoseidonConstants;
    use plonk_hashing::poseidon::poseidon::NativeSpec;
    use plonk_hashing::poseidon::poseidon::Poseidon;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;

    // white list addresses
    let mut rng = rand::thread_rng();
    let white_list = (0..4).map(|_| F::rand(&mut rng)).collect::<Vec<F>>();

    // a note owned by one of the white list user
    let note = Note::<CP>::new(
        white_list[1],
        F::rand(&mut rng),
        12,
        <CP as CircuitParameters>::CurveScalarField::rand(&mut rng),
        <CP as CircuitParameters>::CurveScalarField::rand(&mut rng),
        &mut rng,
    );
    let note_com = note.commitment();

    // I wanted to use hash_two but I was not able...
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    let mut poseidon = Poseidon::<(), NativeSpec<F, WIDTH_3>, WIDTH_3>::new(
        &mut (),
        &poseidon_hash_param_bls12_377_scalar_arity2,
    );
    let _ = poseidon.input(white_list[2]);
    let _ = poseidon.input(white_list[3]);
    let hash_2_3 = poseidon.output_hash(&mut ());

    let mut auth_path: Vec<(Node<_, _>, bool)> = vec![];
    auth_path.push((Node::<F, PoseidonConstants<_>>::new(white_list[0]), true));
    auth_path.push((Node::<F, PoseidonConstants<_>>::new(hash_2_3), false));

    let merkle_path = MerklePath::from_path(auth_path);

    let mut composer = StandardComposer::<F, <CP as CircuitParameters>::InnerCurve>::new();
    white_list_gadget::<F, P, PoseidonConstants<F>, CP>(
        &mut composer,
        note,
        merkle_path,
        white_list,
        note_com,
    );
    composer.check_circuit_satisfied();
}
