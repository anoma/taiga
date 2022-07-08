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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
    use crate::merkle_tree::MerkleTreeLeafs;
    use crate::note::Note;
    use crate::nullifier::Nullifier;
    use crate::token::Token;
    use crate::user::User;
    use ark_std::test_rng;
    use ark_std::UniformRand;
    use plonk_core::constraint_system::StandardComposer;
    use plonk_hashing::poseidon::constants::PoseidonConstants;
    use rand::Rng;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;

    pub fn dummy_note(user: User<CP>) -> Note<CP> {
        let mut rng = test_rng();
        let token = Token::<CP>::new(&mut rng);
        let rho = Nullifier::new(F::rand(&mut rng));
        let value: u64 = rng.gen();
        let data = F::rand(&mut rng);
        let rcm = F::rand(&mut rng);
        Note::new(user, token, value, rho, data, rcm)
    }

    #[test]
    fn test_white_list_gadget() {
        let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();

        // white list addresses and mk root associated
        let mut rng = rand::thread_rng();
        let white_list: Vec<User<CP>> = (0..4).map(|_| User::<CP>::new(&mut rng)).collect();
        // user addresses
        let white_list_f: Vec<F> = white_list.iter().map(|v| v.address().unwrap()).collect();

        let mk_root = MerkleTreeLeafs::<F, PoseidonConstants<F>>::new(white_list_f.to_vec())
            .root(&poseidon_hash_param_bls12_377_scalar_arity2);

        let user = white_list[1];

        // a note owned by one of the white list user
        let note = dummy_note(user);

        let merkle_path: MerklePath<F, PoseidonConstants<_>> =
            MerklePath::build_merkle_path(white_list_f, 1);

        // wrap the private input as slice of F elements
        let mut private_inputs: Vec<F> = vec![note.user.address().unwrap()];
        for (x, y) in merkle_path.get_path() {
            private_inputs.push(x);
            private_inputs.push(F::from(y));
        }

        let mut composer = StandardComposer::<F, P>::new();
        let root_var = white_list_gadget::<F, P, PoseidonConstants<F>, CP>(
            &mut composer,
            &private_inputs,
            &[],
        );

        let expected_var = composer.add_input(mk_root.inner());
        composer.assert_equal(expected_var, root_var);

        composer.check_circuit_satisfied();
    }
}
