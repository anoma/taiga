# Validity predicates

A **validity predicate** (VP) is a piece of code that authorizes transactions by checking its input and output notes. In order to be authorized, a transaction must satisfy all of the constraints of VPs of parties involved.

Examples of such constraints would be a white list VP that allows only specific users to send notes to the VP owner, or a lower bound VP that restricts the smallest amount of asset that can be received.

### Validity predicates in Taiga
Currently, every user in Taiga [has two VPs](./users.md): one that authorizes spending notes (`SendVP`), and one that authorizes receiving notes (`RecvVP`). [Tokens](./token.md) in Taiga also have validity predicates, and spending or receiving a note of a particular token requires satisfying the `TokenVP`.

### Shielded VPs
For each transaction, it must be proven that all of the VPs of parties and tokens involved are satisfied. To preserve privacy, ZK proofs are used. The transaction is authorized only if all of the produced proofs are verified successfully.

![img.png](img/vp_img.png)

## Example

Every validity predicate structure has input and output notes of the transaction as the local data (to be checked against the constraints).
```rust
pub struct TrivialValidityPredicate<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}
```
Let's define a trivial VP that checks nothing and returns true:
```rust
impl<CP: CircuitParameters> Circuit<CP::CurveScalarField, CP::InnerCurve> for TrivialValidityPredicate<CP>
{
    ...
    
    //the VP constraints are defined here
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
From this gadget representing the VP constraints, we can compute the VP proof and verify it:
```rust
// creation of the VP
let mut vp = TrivialValidityPredicate::<CP> { input_notes, output_notes };

// setup of the proof system
let vp_setup = PC::setup(vp.padded_circuit_size(), None, &mut rng).unwrap();

// compute proving and verifying keys
let (pk, vk) = vp.compile::<PC>(&vp_setup).unwrap();

// generate the proof
let (proof, public_inputs) = vp.gen_proof::<PC>(&vp_setup, pk, b"Test").unwrap();

// verify the proof to make sure the VP is satisfied
let verifier_data = VerifierData::new(vk, public_inputs);
verify_proof::<Fr, P, PC>(
    &vp_setup,
    verifier_data.key,
    &proof,
    &verifier_data.pi,
    b"Test",
).unwrap();
```

This example can be run with [this file](https://github.com/anoma/taiga/blob/main/src/doc_examples/validity_predicate.rs) or with the command line
```
cargo test doc_examples::validity_predicate::test_vp_creation
```
Next: [Token](./token.md)