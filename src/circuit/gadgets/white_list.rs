use crate::circuit::circuit_parameters::CircuitParameters;
use crate::merkle_tree::MerklePath;
use crate::merkle_tree::Node;
use crate::poseidon::WIDTH_3;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::Variable;
use plonk_core::prelude::StandardComposer;
use plonk_hashing::poseidon::constants::PoseidonConstants;

use super::hash::FieldHasherGadget;
use super::merkle_tree::merkle_tree_gadget;

pub fn white_list_gadget<
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    BHG: FieldHasherGadget<F, P>,
    CP: CircuitParameters<CurveScalarField = F, InnerCurve = P>,
>(
    composer: &mut StandardComposer<F, P>,
    private_inputs: &[F],
    _public_inputs: &[F],
) -> Variable {
    // TODO prove note ownership

    // wrap private inputs in the format of the proof
    let owner_variable = composer.add_input(private_inputs[0]);
    let mut v: Vec<(Node<F, PoseidonConstants<F>>, bool)> = vec![];
    let mut i = 1;
    while i < 5 {
        v.push((
            Node::<F, PoseidonConstants<_>>::new(private_inputs[i]),
            !private_inputs[i + 1].is_zero(),
        ));
        i += 2;
    }
    let merkle_path = MerklePath::from_path(v);

    // merkle tree gadget for white list membership
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();
    merkle_tree_gadget::<F, P, PoseidonConstants<F>>(
        composer,
        &owner_variable,
        &merkle_path.get_path(),
        &poseidon_hash_param_bls12_377_scalar_arity2,
    )
    .unwrap()
}

#[test]
fn test_white_list_gadget() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::merkle_tree::MerkleTreeLeafs;
    use crate::merkle_tree::Node;
    use crate::note::Note;
    use crate::nullifier::Nullifier;
    use crate::poseidon::FieldHasher;
    use crate::token::TokenAddress;
    use crate::user_address::UserAddress;
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;
    use plonk_hashing::poseidon::constants::PoseidonConstants;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;

    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();

    // white list addresses and mk root associated
    let mut rng = rand::thread_rng();
    let white_list: Vec<UserAddress<CP>> =
        (0..4).map(|_| UserAddress::<CP>::new(&mut rng)).collect();
    let white_list_f: Vec<F> = white_list
        .iter()
        .map(|v| v.opaque_native().unwrap())
        .collect();
    let mk_root = MerkleTreeLeafs::<F, PoseidonConstants<F>>::new(white_list_f.to_vec())
        .root(&poseidon_hash_param_bls12_377_scalar_arity2);

    // a note owned by one of the white list user
    let token = TokenAddress::<CP>::new(&mut rng);
    let rho = Nullifier::new(F::rand(&mut rng));
    let value = 12u64;
    let data = F::rand(&mut rng);
    let rcm = F::rand(&mut rng);
    let note = Note::new(white_list[1], token, value, rho, data, rcm);

    // I wanted to use hash_two but I was not able...
    let hash_2_3 = PoseidonConstants::generate::<WIDTH_3>()
        .native_hash_two(&white_list_f[2], &white_list_f[3])
        .unwrap();

    let auth_path = &[
        (Node::<F, PoseidonConstants<_>>::new(white_list_f[0]), true),
        (Node::<F, PoseidonConstants<_>>::new(hash_2_3), false),
    ];

    let merkle_path = MerklePath::from_path(auth_path.to_vec());

    // wrap the private input as slice of F elements
    let mut private_inputs: Vec<F> = vec![note.address.opaque_native().unwrap()];
    for (x, y) in merkle_path.get_path() {
        private_inputs.push(x);
        private_inputs.push(F::from(y));
    }

    let mut composer = StandardComposer::<F, <CP as CircuitParameters>::InnerCurve>::new();
    let root_var =
        white_list_gadget::<F, P, PoseidonConstants<F>, CP>(&mut composer, &private_inputs, &[]);

    let expected_var = composer.add_input(mk_root.inner());
    composer.assert_equal(expected_var, root_var);

    composer.check_circuit_satisfied();
}
