# Zero-knowledge proofs

## ZK proofs in a nutshell
Zero-knowledge proofs are new cryptographic primitives leading to very useful applications. Two entities called *prover* and *verifier* interact.
They both know an arithmetic circuit and the prover knows a witness for the circuit. It means that plugging the witness into the circuit makes the circuit consistent. The verifier computes the verifier key from the circuit, and can verify a proof using the verifier key. 
* Setting. The prover and the verifier know a circuit $\mathcal C$. The verifier key can be derived as $\text{vk} = \text{Precomputation}(\mathcal C)$.
* Proof. The prover computes a proof $π$ of from the circuit $\mathcal C$ and the witness $ω$: $π = \text{Proof}(ω, \mathcal C)$.
* Verification. The verifier can check the proof by computing the boolean $\text{Verify}(π, \text{vk})$.

From now on, we call *validity predicate* the entire data corresponding to a proof (the circuit, the proof, and the verifier key).

## A simple example
The above construction is very abstract and we provide here a simple example of an addition.
The arithmetic circuit is simply an integer addition $a+b = c$. The integer $c$ is a public value known by the prover and the verifier, while $a$ and $b$ are witnesses known only by the prover. The prover wants to convince the verifier that he knows $a$ and $b$ without revealing them.
```rust

pub struct AdditionCircuit<F:PrimeField> {
    a: F,
    b: F,
    pub c: F,
}

let mut rng = test_rng();
let a = F::rand(&mut rng);
let b = F::rand(&mut rng);
let c = a + b;

let mut circuit = AdditionCircuit::<F> { a, b, c };
```

The arithmetic circuit can be seen as an array of integers corresponding to an addition. Depending on the ZK proof construction we use, the circuit has a different shape but for now we can consider it as an array where each row corresponds to a gate of the form $αx + βy = γ$. Thus, the circuit has three columns correspond to $α$, $β$ and $γ$. In the case of our example, the circuit has only one gate corresponding to:

|α|β|γ|x|y|
|-|-|-|-|-|
|1|1|c|a|b|

We use the `Circuit` implementation from ZK-Garage in order to create the circuit:

```rust
fn gadget(
    &mut self,
    composer: &mut StandardComposer<F, P>,
) -> Result<(), Error> {
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
```

The prover computes the proof $π$. The proof uses the circuit $\mathcal C$ and the witness $ω$ and outputs $π$, the zero-knowledge proof.
```rust
// Setup
let setup = PC::setup(Circuit::<F, P>::padded_circuit_size(&circuit), None, &mut rng).unwrap();
// Prover and verifier key
let (pk, vk) = Circuit::<F, P>::compile::<PC>(&mut circuit, &setup).unwrap();
// Proof computation
let (pi, public_inputs) = Circuit::<F, P>::gen_proof::<PC>(&mut circuit, &setup, pk, b"Test").unwrap();
```

The verifier uses the proof $π$ and the verifier key $\text{vk}$ (a precomputation of $\mathcal C$) in order to check whether if $\text{Verify}(π, \text{vk})$ is true.
```rust
// Proof verification
let verifier_data = VerifierData::new(vk, public_inputs);
verify_proof::<F, P, PC>(&setup, verifier_data.key, &pi, &verifier_data.pi, b"Test").unwrap();
```

This example can be run with [this file](../../src/doc_test_simple_example.rs) or with the command line
```
cargo test test_circuit_example
```

## ZK proofs in Taiga
ZK proofs are the main ingredient of Taiga:
* Users and applications can provide their own rules for the transaction. A user defines rules for sending and receiving notes. As an example, a receiving VP could be a check that the sent notes contains at least 3 applications.
* Binding notes, users and applications is done using hash commitments. We use ZK proofs in order to get full privacy. We will investigate further these definitions in the next sections.