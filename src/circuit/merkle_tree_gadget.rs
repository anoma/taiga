use crate::poseidon::{POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2, WIDTH_3};
use ark_bls12_377::Fr;
use ark_ed_on_bls12_377::EdwardsParameters as Curv;
use ark_ff::{One, Zero};
use plonk_core::{constraint_system::StandardComposer, error::Error, prelude::Variable};
use plonk_hashing::poseidon::poseidon::{PlonkSpec, Poseidon};

pub fn merkle_tree_gadget(
    composer: &mut StandardComposer<Fr, Curv>,
    cur_leaf: &Variable,
    auth_path: &Vec<(Fr, bool)>, // hash_gadget
) -> Result<Variable, Error> {
    let mut cur = *cur_leaf;

    // Ascend the merkle tree authentication path
    for e in auth_path.iter() {
        // Determines if the current subtree is the "right" leaf at this
        // depth of the tree.
        let cur_is_right = match e.1 {
            false => composer.add_input(Fr::zero()),
            true => composer.add_input(Fr::one()),
        };

        // Witness the authentication path element adjacent
        // at this depth.
        let path_element = composer.add_input(e.0);

        // Swap the two if the current subtree is on the right
        let ul = composer.conditional_select(cur_is_right, path_element, cur);
        let ur = composer.conditional_select(cur_is_right, cur, path_element);

        // Compute the new subtree value
        // cur = hash_gadget.hash_two(composer, ul, ur)?;
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(
            composer,
            &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
        );
        poseidon_circuit.input(ul).unwrap();
        poseidon_circuit.input(ur).unwrap();

        cur = poseidon_circuit.output_hash(composer);
    }

    Ok(cur)
}

#[test]
fn test_merkle_circuit() {
    use crate::merkle_tree::{MerklePath, Node};
    use ark_std::test_rng;
    use plonk_hashing::poseidon::constants::PoseidonConstants;

    let mut rng = test_rng();
    let merkle_path = MerklePath::<Fr, PoseidonConstants<Fr>>::dummy(&mut rng);

    let cur_leaf = Node::rand(&mut rng);
    let expected = merkle_path.root(
        cur_leaf.clone(),
        &POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2,
    );

    let mut composer = StandardComposer::<Fr, Curv>::new();
    let commitment = composer.add_input(cur_leaf.inner());
    let root = merkle_tree_gadget(&mut composer, &commitment, &merkle_path.get_path()).unwrap();
    composer.check_circuit_satisfied();

    let expected_var = composer.add_input(expected.inner());
    composer.assert_equal(expected_var, root);
    composer.check_circuit_satisfied();

    println!("circuit size for merkel tree: {}", composer.circuit_bound());
}
