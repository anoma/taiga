use crate::poseidon::WIDTH_3;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{constraint_system::StandardComposer, prelude::Variable};
use plonk_hashing::poseidon::constants::PoseidonConstants;
use plonk_hashing::poseidon::poseidon::{PlonkSpec, Poseidon};
use plonk_hashing::poseidon::PoseidonError;

pub trait BinaryHasherGadget<F: PrimeField, P: TEModelParameters<BaseField = F>> {
    fn hash_two(
        &self,
        composer: &mut StandardComposer<F, P>,
        left: &Variable,
        right: &Variable,
    ) -> Result<Variable, PoseidonError>;
}

impl<F: PrimeField, P: TEModelParameters<BaseField = F>> BinaryHasherGadget<F, P>
    for PoseidonConstants<F>
{
    fn hash_two(
        &self,
        composer: &mut StandardComposer<F, P>,
        left: &Variable,
        right: &Variable,
    ) -> Result<Variable, PoseidonError> {
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(composer, &self);
        poseidon_circuit.input(*left)?;
        poseidon_circuit.input(*right)?;

        Ok(poseidon_circuit.output_hash(composer))
    }
}
