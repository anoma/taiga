# Validity predicates

Validity predicates are constrains defined by entities of Taiga in order to approve transactions. Examples of constrains can be a white list of allowed senders of notes, or a lower bound on the amount of received notes.

From the constrains and a given transaction, a user (or a token) produces a zero-knowledge proof for allowing the transaction. A user can verifiy the proof against a verifier key, computed from the constrains. Verifying a proof leads to a boolean and transactions are validated if and only if all the proofs pass the verification.

```
TODO Add a diagram:
constrains -----------> VK------------
                |                     |------> True/False
                |                     |
tx-------------------> proof----------
```

## Example

We define a first validity predicate. It has fields corresponding to the input and output notes of the transaction.
```rust
pub struct TrivialValidityPredicate<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}
```
We begin with a very simple VP that actually does not check any constrain on the notes:
```rust
impl<CP: CircuitParameters> Circuit<CP::CurveScalarField, CP::InnerCurve> for TrivialValidityPredicate<CP>
{
    ...
    
    fn gadget(
        &mut self,
        _composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        // do nothing and return Ok()
        Ok(())
    }
   ... 
}
```
From this gadget representing the circuit, we can compute a proof and verify it with the verifier key:
```rust
// creation of the VP
let mut vp = TrivialValidityPredicate::<CP> { input_notes, output_notes };

// setup of the proof system
let vp_setup = PC::setup(vp.padded_circuit_size(), None, &mut rng).unwrap();

// proving and verifying keys
let (pk, vk) = field_addition_vp.compile::<PC>(&vp_setup).unwrap();

// proof
let (proof, public_inputs) = vp.gen_proof::<PC>(&vp_setup, pk, b"Test").unwrap();

// verification
let verifier_data = VerifierData::new(vk, public_inputs);
verify_proof::<Fr, P, PC>(
    &vp_setup,
    verifier_data.key,
    &proof,
    &verifier_data.pi,
    b"Test",
).unwrap();
```

This example can be run with [this file](../../src/doc_test_simple_example.rs) or with the command line
```
cargo test test_vp_example
```

TODO CODE SIMON

## Validity predicates in Taiga
Validity predicates are the main ingredients of Taiga:
* Users and tokens can provide their own rules for the transaction. A user defines rules for sending and receiving notes. As an example, a receiving VP could be a check that the sent notes contains at least 3 tokens.
* Binding notes, users and tokens is done using commitments. We use the same kind of circuits in order to prove the bindings and for getting full privacy. We will investigate further these definitions in the next sections.