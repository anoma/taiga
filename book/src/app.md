# Application

Similarly to Ethereum applications that are build on smart contracts, Taiga applications have VPs that define the application rules. Every application is identified by its address and has its own note type. Sending and receiving the notes of the app type is controlled by the `appVP`.

#### Example
- a cryptocurrency application with a note type CUR (matches the token name) and `appVP` that makes sure that the balance is correct

### Application VP
Each application has its own [`appVP`](./validity-predicates.md) that defines the conditions on which the application can be used (i.e. the notes of the corresponding type can be sent or received). 

Like all other VPs, `appVP` is required to evaluate to `true` in a valid transaction and shielded with the help of ZK proofs.

#### Application Address
Each application is identified by an address that is derived from its verifier key `app_VK` (that is itself derived from the `appVP`):
`appAddress = Com(app_VK)`. Notes are linked to applications through the app address field of a note. 

TODO: link to a VK definition

### Examples
##### Create an application
As `appVP` basically defines the application, creating an application is done by creating its `appVP`.

Let's use the [`TrivialValidityPredicate`](./validity-predicates.md) we defined earlier. It does nothing and returns `true`:
```rust
// trivial VP checks nothing and returns Ok()
let mut app_vp = TrivialValidityPredicate::<CP> {
	input_notes,
	output_notes,
};

// transform the VP into a circuit description
let desc_vp = ValidityPredicateDescription::from_vp(&mut app_vp, &vp_setup).unwrap();

let app = App::<CP>::new(desc_vp);

//app address can be used to create notes of that app
let app_address = app.address().unwrap();
```
See the example code [here](https://github.com/anoma/taiga/blob/main/taiga_zk_garage/src/doc_examples/app.rs)

#### Dummy application

It is also possible to create a dummy application without a VP (used to create dummy notes):

```rust
let app = App::<CP>::dummy(&mut rng)
```
