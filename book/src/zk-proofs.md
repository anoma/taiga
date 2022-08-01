# Zero-knowledge proofs

## ZK proofs in a nutshell
Zero-knowledge proofs are new cryptographic primitives leading to very useful applications. Two entities called *prover* and *verifier* interact.
They both know an arithmetic circuit and the prover knows a witness for the circuit. It means that pluging the witness into the circuit makes the circuit consistent. The verifier computes the verifier key from the circuit, and can verify a proof using the verifier key. 
* Setting. The prover and the verifier know a circuit $\mathcal C$. The verifier key can be derived as $\text{vk} = \text{Precomputation}(\mathcal C)$.
* Proof. The prover computes a proof $π$ of from the circuit $\mathcal C$ and the witness $ω$: $π = \text{Proof}(ω, \mathcal C)$.
* Verification. The verifier can check the proof by computing the boolean $\text{Verify}(π, \text{vk})$.

From now on, we call *validity predicate* the entire data corresponding to a proof (the circuit, the proof, and the verifier key).

## A simple example
The above construction is very abstract and we provide here a simple example of an addition.
* The arithmetic circuit is simply an integer addition $a+b = c$.
    * The integer $c$ is a public value known by the prover and the verifier, while $a$ and $b$ are witnesses known only by the prover. The prover wants to convince the verifier that he knows $a$ and $b$ without revealing them.
    * The arithmetic circuit can be seen as an array of integers corresponding to an addition. Depending on the ZK proof construction we use, the circuit has a different shape but for now we can consider it as an array where each row corresponds to a gate of the form $αx + βy = γ$. Thus, the circuit has three columns correspond to $α$, $β$ and $γ$. In the case of our example, the circuit has only one gate corresponding to:

|α|β|γ|x|y|
|-|-|-|-|-|
|1|1|c|a|b|

* Proof. The prover computes the proof $π$. The proof uses the circuit $\mathcal C$ and the witness $ω$ and outputs $π$, the zero-knowledge proof.
* Verification. The verifier uses the proof $π$ and the verifier key $\text{vk}$ (a precomputation of $\mathcal C$) in order to check whether if $\text{Verify}(π, \text{vk})$ is true.
```rust
use crate::circuit::*;
```
We can build the addition validty predicate in Taiga as follows:
```rust

use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::gadgets::field_addition::field_addition_gadget;
use crate::circuit::gadgets::trivial::trivial_gadget;
use crate::circuit::integrity::{
    ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
};
use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
use crate::note::Note;
use crate::poseidon::WIDTH_3;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};

pub struct AdditionCircuit<CP: CircuitParameters> {
    a: CP::CurveScalarField,
    b: CP::CurveScalarField,
    pub c: CP::CurveScalarField,
}

impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for AdditionCircuit<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        let var_a = composer.add_input(self.a);
        let var_b = composer.add_input(self.b);
        let var_c = composer.add_input(self.c);

        // add a gate for the addition
        let var_a_plus_b = field_addition_gadget::<CP>(composer, var_a, var_b);

        composer.assert_equal(var_a_plus_b, var_c);
        composer.check_circuit_satisfied();
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 3
    }
}

#[test]
fn test_circuit_example() {
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
    let mut circuit = AdditionCircuit::<CP> { a, b, c };

    // Setup
    let setup = PC::setup(circuit.padded_circuit_size(), None, &mut rng).unwrap();

    // Prover and verifier key
    let (pk, vk) = circuit.compile::<PC>(&setup).unwrap();

    // Proof computation
    let (pi, public_inputs) = circuit.gen_proof::<PC>(
        &setup, 
        pk, 
        b"Test"
    ).unwrap();

    // Proof verification
    let verifier_data = VerifierData::new(vk, public_inputs);
    verify_proof::<F, P, PC>(
        &setup, 
        verifier_data.key, 
        &pi, 
        &verifier_data.pi, 
        b"Test"
    ).unwrap();
}
```


* Why we use zk-proofs in taiga (rules of users/tokens, binding and blinding)
* Define a ZK-proof (high level) with witness, proof, verifier key and verification. 
* Provide the example of `a+b==c`, with `cargo test`.