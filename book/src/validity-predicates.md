# Validity predicates

A validity predicate (VP) is a circuit living inside a note that has access to the contents of all the notes involved in a transaction. A transaction is valid if and only if all the VPs of the notes it contains are satisfied and the note `values` are balanced (see notes).


<!-- TODO: Code these examples and add a link to them here -->
Examples of VPs are:
- Whitelist sending addresses
- Whitelist asset types
- Content-based multi-signature check
- Subscription
- Conditional spend/joint funding of public good
- Check transaction is balanced
- Shield/Unshield tokens


## The anatomy of a VP

The VP follows closely the Halo2 API, plus adding the note-related methods that characterise a VP.

#### ValidityPredicateConfig

```rust
pub trait ValidityPredicateConfig {
    fn configure_note(meta: &mut ConstraintSystem<pallas::Base>) -> NoteConfig;
    fn get_note_config(&self) -> NoteConfig;
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self;
}
```

- `configure` calls `ConstraintSystem`, that is, the description of the information of a circuit, to set values for `Column` and `Gate` and thus describe the exact gate arrangement, column arrangement, etc. Calling the `configure` function of a circuit will sequentially utilize the `configure` information of the corresponding `Chip`. This method is left without a default implementation, since it's completely dependent of the application at hand.
- `configure_note` behaves like as `configure` but it's particular to configuring a note chip. A default implementation is provided since it's likely to work in the same way for all types of applications.
- `get_note_config` is a simple getter, since the application config that implements `ValidityPredicateConfig` will have a field of type `NoteConfig`.

#### ValidityPredicateConfig

```rust
pub trait ValidityPredicateInfo: DynClone {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE];
    fn get_output_notes(&self) -> &[Note; NUM_NOTE];
    fn get_note_instances(&self) -> Vec<pallas::Base>;
    fn get_instances(&self) -> Vec<pallas::Base>;
    fn get_verifying_info(&self) -> VPVerifyingInfo;
    fn get_vp_description(&self) -> ValidityPredicateDescription;
}
```

- `get_spend_notes` and `get_output_notes` are simple getters.
- `get_note_instances`
- `get_verifying_info` constructs the necessary information to verify a validity predicate, that is, the proof of the circuit, its verifying key and its instances.
- `get_vp_description` constructs the verifying key of the VP.

```rust
pub trait ValidityPredicateCircuit: Circuit<pallas::Base> + ValidityPredicateInfo {
    type VPConfig: ValidityPredicateConfig + Clone;
    // Default implementation, constrains the notes integrity.
    // TODO: how to enforce the constraints in vp circuit?
    fn basic_constraints(
        &self,
        config: Self::VPConfig,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(Vec<SpendNoteVar>, Vec<OutputNoteVar>), Error>;

    fn custom_constraints(
        &self,
        _config: Self::VPConfig,
        mut _layouter: impl Layouter<pallas::Base>,
        _spend_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), Error>;
}
```

- `basic_contraints` constrains the notes integrity. A default implementation is provided
- `custom_constraints` provides the application specific constraints. Informally, it corresponds to the `synthesise` method in Halo2 from the user's perspective.

### Application VPs and Sub VPs

There are two types of validity predicates inside a note:
- An Application VP
- A Sub VP

### Example of an application VP: Sudoku intent
The constraints in this application VP are:
- Check that `vp_data` is encoded correctly - `vp_data` encodes the Sudoku puzzle to make the note value base unique
- If one of the notes (there are four notes in a VP) is an output note of Sudoku (created by the dealer), check the validity of the puzzle
- If one of the 4 output notes is a spent note of Sudoku (spent by the player/solver), check the correctness of the solution

### Shielded VPs
For each transaction, it must be proven that all of the VPs of parties and apps involved are satisfied. To preserve privacy, ZK proofs are used. The transaction is authorized only if all of the produced proofs are verified successfully.

![img.png](img/vp_img.png)

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