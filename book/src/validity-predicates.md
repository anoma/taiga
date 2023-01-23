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

<!-- TODO: Explain further -->
### Example of an application VP: Sudoku intent
The constraints in this application VP are:
- Check that `vp_data` is encoded correctly - `vp_data` encodes the Sudoku puzzle to make the note value base unique
- If one of the notes (there are four notes in a VP) is an output note of Sudoku (created by the dealer), check the validity of the puzzle
- If one of the 4 output notes is a spent note of Sudoku (spent by the player/solver), check the correctness of the solution

## Example

See a trivial example [here](../../taiga_halo2/src/circuit/vp_examples.rs)

Next: [App](./app.md)