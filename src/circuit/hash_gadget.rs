use crate::error::TaigaError;
use crate::poseidon::WIDTH_3;
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{constraint_system::StandardComposer, prelude::Variable};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{PlonkSpec, Poseidon},
};

/// A BinaryHasherGadget takes two variables as input and outputs the hash
/// result variable.
pub trait BinaryHasherGadget<F: PrimeField, P: TEModelParameters<BaseField = F>> {
    fn circuit_hash_two(
        &self,
        composer: &mut StandardComposer<F, P>,
        left: &Variable,
        right: &Variable,
    ) -> Result<Variable, TaigaError>;
}

/// A BinaryHasherGadget implementation for Poseidon hash.
impl<F: PrimeField, P: TEModelParameters<BaseField = F>> BinaryHasherGadget<F, P>
    for PoseidonConstants<F>
{
    fn circuit_hash_two(
        &self,
        composer: &mut StandardComposer<F, P>,
        left: &Variable,
        right: &Variable,
    ) -> Result<Variable, TaigaError> {
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(composer, &self);
        poseidon_circuit.input(*left)?;
        poseidon_circuit.input(*right)?;

        Ok(poseidon_circuit.output_hash(composer))
    }
}
