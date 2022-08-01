use crate::circuit::gadgets::hash::FieldHasherGadget;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{
    constraint_system::StandardComposer,
    prelude::{Error, Variable},
};

/// A Merkle Tree Gadget takes leaf node variable, authorization path to the
/// root and the FieldHasherGadget, then returns the merkle root variable.
pub fn merkle_tree_gadget<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    BHG: FieldHasherGadget<F, P>,
>(
    composer: &mut StandardComposer<F, P>,
    cur_leaf: &Variable,
    auth_path: &[(F, bool)],
    hash_gadget: &BHG,
) -> Result<Variable, Error> {
    let mut cur = *cur_leaf;

    // Ascend the merkle tree authentication path
    for e in auth_path.iter() {
        // Determines if the current subtree is the "right" leaf at this
        // depth of the tree.
        let cur_is_right = match e.1 {
            false => composer.add_input(F::zero()),
            true => composer.add_input(F::one()),
        };

        // Witness the authentication path element adjacent
        // at this depth.
        let path_element = composer.add_input(e.0);

        // Swap the two if the current subtree is on the right
        let ul = composer.conditional_select(cur_is_right, path_element, cur);
        let ur = composer.conditional_select(cur_is_right, cur, path_element);

        // Compute the new subtree value
        cur = hash_gadget.circuit_hash_two(composer, &ul, &ur)?;
    }

    Ok(cur)
}

#[test]
fn test_merkle_circuit() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
    use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;
    use crate::merkle_tree::{MerklePath, Node};
    use crate::poseidon::POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY2;
    type Fr = <PairingCircuitParameters as CircuitParameters>::CurveScalarField;
    type P = <PairingCircuitParameters as CircuitParameters>::InnerCurve;
    use ark_std::test_rng;
    use plonk_hashing::poseidon::constants::PoseidonConstants;

    let mut rng = test_rng();
    let merkle_path =
        MerklePath::<Fr, PoseidonConstants<Fr>>::dummy(&mut rng, TAIGA_COMMITMENT_TREE_DEPTH);

    let cur_leaf = Node::rand(&mut rng);
    let expected = merkle_path
        .root(
            cur_leaf.clone(),
            &POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY2,
        )
        .unwrap();

    let mut composer = StandardComposer::<Fr, P>::new();
    let commitment = composer.add_input(cur_leaf.inner());
    let root = merkle_tree_gadget::<Fr, P, PoseidonConstants<Fr>>(
        &mut composer,
        &commitment,
        &merkle_path.get_path(),
        &POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY2,
    )
    .unwrap();
    composer.check_circuit_satisfied();

    let expected_var = composer.add_input(expected.inner());
    composer.assert_equal(expected_var, root);
    composer.check_circuit_satisfied();

    println!("circuit size for merkel tree: {}", composer.circuit_bound());
}
