use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::prelude::{Circuit, Error, StandardComposer};

pub struct AdditionCircuit<F: PrimeField> {
    a: F,
    b: F,
    pub c: F,
}

impl<F, P> Circuit<F, P> for AdditionCircuit<F>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let var_a = composer.add_input(self.a);
        let var_b = composer.add_input(self.b);
        // add a gate for the addition
        let var_zero = composer.zero_var();
        // Make first constraint a + b = c (as public input)
        composer.arithmetic_gate(|gate| {
            gate.witness(var_a, var_b, Some(var_zero))
                .add(F::one(), F::one())
                .pi(-self.c)
        });
        composer.check_circuit_satisfied();
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 3
    }
}

#[test]
fn test_circuit_example() {
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    type F = <CP as CircuitParameters>::CurveScalarField;
    type P = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    use ark_poly_commit::PolynomialCommitment;
    use ark_std::{test_rng, UniformRand};
    use plonk_core::circuit::{verify_proof, VerifierData};

    let mut rng = test_rng();
    let a = F::rand(&mut rng);
    let b = F::rand(&mut rng);
    let c = a + b;

    // Circuit
    let mut circuit = AdditionCircuit::<F> { a, b, c };
    // Setup
    let setup = PC::setup(
        Circuit::<F, P>::padded_circuit_size(&circuit),
        None,
        &mut rng,
    )
    .unwrap();
    // Prover and verifier key
    let (pk, vk) = Circuit::<F, P>::compile::<PC>(&mut circuit, &setup).unwrap();
    // Proof computation
    let (pi, public_inputs) =
        Circuit::<F, P>::gen_proof::<PC>(&mut circuit, &setup, pk, b"Test").unwrap();
    // Proof verification
    let verifier_data = VerifierData::new(vk, public_inputs);
    verify_proof::<F, P, PC>(&setup, verifier_data.key, &pi, &verifier_data.pi, b"Test").unwrap();
}
