use crate::error::TaigaError;
use crate::poseidon::{WIDTH_3, WIDTH_5};
use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{constraint_system::StandardComposer, prelude::Variable};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{PlonkSpec, Poseidon},
};

/// A FieldHasherGadget takes field variables as input and outputs
/// the result variable. `circuit_hash_two` takes two field variables;
/// `circuit_hash` takes at most four field variables.
pub trait FieldHasherGadget<F: PrimeField, P: TEModelParameters<BaseField = F>> {
    fn circuit_hash_two(
        &self,
        composer: &mut StandardComposer<F, P>,
        left: &Variable,
        right: &Variable,
    ) -> Result<Variable, TaigaError>;

    fn circuit_hash(
        &self,
        composer: &mut StandardComposer<F, P>,
        inputs: &[Variable],
    ) -> Result<Variable, TaigaError>;
}

/// A FieldHasherGadget implementation for Poseidon hash.
impl<F: PrimeField, P: TEModelParameters<BaseField = F>> FieldHasherGadget<F, P>
    for PoseidonConstants<F>
{
    fn circuit_hash_two(
        &self,
        composer: &mut StandardComposer<F, P>,
        left: &Variable,
        right: &Variable,
    ) -> Result<Variable, TaigaError> {
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(composer, self);
        poseidon_circuit.input(*left)?;
        poseidon_circuit.input(*right)?;

        Ok(poseidon_circuit.output_hash(composer))
    }

    fn circuit_hash(
        &self,
        composer: &mut StandardComposer<F, P>,
        inputs: &[Variable],
    ) -> Result<Variable, TaigaError> {
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_5>, WIDTH_5>::new(composer, self);
        // Default padding zero
        inputs.iter().for_each(|f| {
            poseidon_circuit.input(*f).unwrap();
        });
        Ok(poseidon_circuit.output_hash(composer))
    }
}
