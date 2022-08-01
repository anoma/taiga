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
    |α|β|γ||x|y|
    |-|-|-||-|-|
    |1|1|c||a|b|
* Proof. The prover computes the proof $π$. The proof uses the circuit $\mathcal C$ and the witness $ω$ and outputs $π$, the zero-knowledge proof.
* Verification. The verifier uses the proof $π$ and the verifier key $\text{vk}$ (a precomputation of $\mathcal C$) in order to check whether if $\text{Verify}(π, \text{vk})$ is true.

We can build the addition validty predicate in Taiga as follows:
```rust
use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};
use plonk_core::constraint_system::StandardComposer;
use <CP as CircuitParameters>::CurveScalarField as F;
use <CP as CircuitParameters>::InnerCurve as P;

// create three integers a, b and c such that a + b = c
let a = F::from(2u64);
let b = F::from(1u64);
let c = F::from(3u64);

// create a circuit
let mut circuit = StandardComposer::<F, P>::new();
// add the private and public input to the circuit
let var_a = circuit.add_input(a);
let var_b = circuit.add_input(b);
let var_c = circuit.add_input(c);
// add a gate for the addition
let var_a_plus_b = field_addition_gadget::<CP>(&mut circuit, var_a, var_b);
// check that a + b == c
circuit.assert_equal(var_c, var_a_plus_b);
```

The setup proof verify works as follows:
```rust
// Generate vp CRS
let setup = PC::setup(field_addition_vp.padded_circuit_size(), None, &mut rng).unwrap();

// Compile vp(must use compile_with_blinding)
let (pk_p, vk_blind) = field_addition_vp.compile::<PC>(&vp_setup).unwrap();

// VP Prover
let (proof, pi) = field_addition_vp
    .gen_proof::<PC>(&vp_setup, pk_p, b"Test")
    .unwrap();

// VP verifier
let verifier_data = VerifierData::new(vk_blind, pi);
verify_proof::<Fr, P, PC>(
    &vp_setup,
    verifier_data.key,
    &proof,
    &verifier_data.pi,
    b"Test",
)
.unwrap();
    ```


* Why we use zk-proofs in taiga (rules of users/tokens, binding and blinding)
* Define a ZK-proof (high level) with witness, proof, verifier key and verification. 
* Provide the example of `a+b==c`, with `cargo test`.