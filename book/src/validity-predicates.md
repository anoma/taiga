# Validity predicates

A **validity predicate** (VP) is a piece of code that authorizes transactions by checking its input and output notes. In order to be authorized, a transaction must satisfy all of the constraints of VPs of parties involved.

Examples of such constraints would be a white list VP that allows only specific users to send notes to the VP owner, or a lower bound VP that restricts the smallest amount of asset that can be received.

Taiga validity predicates are intended to be the private version of Anoma's transparent validity predicates. Similarly, Taiga VPs take as input stored state prior and posterior to a transaction execution and either authorize the state change or reject it. Unlike transparent VPs, which execute as WASM, Taiga VPs execute in a zero-knowledge proof/arithmetic circuit model of computation. Because of vastly different nature of the execution model, there are some differences between transparent and Taiga VPs, even if they have similar goals.

### Validity predicates in Taiga

Taiga uses a PLONK-based zero knowledge proof system, and validity predicates are given as [PLONK arithmetizations](https://zcash.github.io/halo2/concepts/arithmetization.html), which is a table of cells with polynomial constraints. For privacy of which validity predicate is used inside of a transaction, all Taiga validity predicates must share the same PLONK configuration (which can be thought of as the set of "gates" available). Different validity predicates are created by specifying the *selectors*.

#### State model in Taiga

Unlike transparent Anoma, which operates on an account model, Taiga uses a note based model. In an account model, each account has associated state which is stored in a database, and updated according to that account's validity predicate. In the note model, however, state is sharded into an append-only set of *note commitments* and revealed *nullifiers*. Each note has exactly one associated nullifier, and the current state of the Taiga is the subset of notes whose nullifiers are not yet revealed, called unspent notes. The Action/Execute circuit, together with the transaction verifier, ensure that the Taiga state is consistent.

### PLONK circuit configuration for validity predicates in Taiga

The validity predicate configuration includes the following "gates" in the PLONK configuration:

* Field addition/multiplication
* Elliptic curve addition and scalar multiplication
* Poseidon hash

#### Addresses

Even though Taiga does not have *accounts*, it does have *addresses*. Each note is associated with one *user address* and one *app address*. Intuitively, a note belongs to the user address and is of a type given by the app address.

Currently, every [user](./users.md) in Taiga has two VPs: one that authorizes spending notes (`SendVP`), and one that authorizes receiving notes (`RecvVP`). [Apps](./app.md) in Taiga also have validity predicates, and spending or receiving a note of a particular app requires satisfying the `TokVP`.

### Shielded VPs
For each transaction, it must be proven that all of the VPs of parties and apps involved are satisfied. To preserve privacy, ZK proofs are used. The transaction is authorized only if all of the produced proofs are verified successfully.

![img.png](img/vp_img.png)

### Transactions

Informally, transactions take a private subset of unspent notes from the Taiga note set, publicly reveal their nullifiers, and reveal a new set of note commitments to add to the Taiga note set. The Action/Execute circuit verifies consistency of this state transition, but does not check directly its validity. Instead, the validity predicate circuits must check the validity of the state transition. The following VPs are called:

* The spending VP for every spent note
* The app VP for every spent and created note
* The receiving VP for every created note

Each VP is called *once* per transaction, even if it is checking multiple *notes*. In addition, VPs are given all notes in the transaction as input, whether or not that note is associated with that *app type* or *user address*.

### VP interface

For privacy and efficiency, all VPs must share the same *public input interface*. VPs may have different *private* inputs.

#### Public Inputs

* $\{nf_i\}$, the set of revealed nullifiers in the transaction
* $\{cm_i\}$, the set of new notes created in the transaction
* $e$, the current Taiga epoch (used for time-tracking)

TODO: This might include a public key as well

#### Typical private inputs

While not required, most validity predicates will take a few typical private inputs:

* $\{(address, app, v, data, rho, psi, rcm)_i\}$ for each spent note in the transaction
* $\{(address, app, v, data, rho, psi, rcm)_j\}$ for each created note in the transaction

The validity predicate must verify (via standardized logic) that the contents of each note match the public $\{nf_i\}$ and $\{cm_i\}$.

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
Next: [App](./app.md)