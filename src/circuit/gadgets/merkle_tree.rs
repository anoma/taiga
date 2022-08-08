use crate::circuit::{gadgets::hash::FieldHasherGadget, load_value::load_private};
use ark_ec::TEModelParameters;
use ff::PrimeField;
use plonk_core::{
    //constraint_system::StandardComposer,
    //prelude::{Error, Variable},
};

use halo2_gadgets::{poseidon::{self, primitives::P128Pow5T3}, utilities::cond_swap::CondSwapChip};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::vesta;

/// A Merkle Tree Gadget takes leaf node variable, authorization path to the
/// root and the FieldHasherGadget, then returns the merkle root variable.
pub fn merkle_tree_gadget<
    F: PrimeField,
    //P: TEModelParameters<BaseField = F>,
    //BHG: FieldHasherGadget<F, P>,
>(
    mut layouter: impl Layouter<F>,
    advice_column: &Column<Advice>,
    cur_leaf: &AssignedCell<F,F>,
    auth_path: &[(F, bool)],
    hash_gadget: &poseidon::Pow5Chip<F, 3 ,2>,
    cond_swap: &CondSwapChip<F>,
) -> Result<AssignedCell<F,F>, Error> {
    let mut cur = *cur_leaf;

    // Ascend the merkle tree authentication path
    for e in auth_path.iter() {
        // Determines if the current subtree is the "right" leaf at this
        // depth of the tree.
        /*let cur_is_right = match e.1 {
            false => load_private(advice_column, layouter, F::zero()), 
            true => load_private(advice_column, layouter,F::one()),
        };*/

        // Witness the authentication path element adjacent
        // at this depth.
        // let path_element = load_private(advice_column, layouter,e.0);

        // Swap the two if the current subtree is on the right
        //let ul = composer.conditional_select(cur_is_right, path_element, cur);
        //let ur = composer.conditional_select(cur_is_right, cur, path_element);

        let (ur, ul) = cond_swap.swap(layouter.namespace(|| "swap"), cur, e.0 ,e.1);

        // Compute the new subtree value
        let poseidon_state = poseidon::Hash::init(hash_gadget, layouter);
        cur = poseidon_state.hash(layouter, [ul, ur])?;
    }

    Ok(cur)
}

#[test]
fn test_merkle_circuit() {
    use crate::circuit::circuit_parameters::{CircuitParameters, HaloCircuitParameters};
    use crate::merkle_tree::TAIGA_COMMITMENT_TREE_DEPTH;
    use crate::merkle_tree::{MerklePath, Node};
    use crate::poseidon::POSEIDON_HASH_PARAM_BLS12_381_NEW_SCALAR_ARITY2;
    type Fr = <HaloCircuitParameters as CircuitParameters>::CurveScalarField;
    type P = <HaloCircuitParameters as CircuitParameters>::InnerCurve;
    use ark_std::test_rng;
    //use plonk_hashing::poseidon::constants::PoseidonConstants;

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
    let commitment = load_private(advice_column, layouter,cur_leaf.inner());
    let root = merkle_tree_gadget::<Fr, P, PoseidonConstants<Fr>>(
        layouter,
        advice_column,
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
