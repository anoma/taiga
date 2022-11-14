# Application

Similarly to Ethereum applications that are build on smart contracts, Taiga applications have VPs that define the application rules. Every application is identified by its address and has its own note type. Sending and receiving the notes of the app type is controlled by the `appVP`.

#### Example
- cryptocurrency application with a note type CUR (matches the token name) and `appVP` that makes sure that the balance is correct

### Application VP
Each application has its own [`appVP`](./validity-predicates.md) that defines the conditions on which the application can be used (i.e. the notes of the corresponding type can be sent or received). 

Like all other VPs, `appVP` is required to evaluate to `true` in a valid transaction and shielded with the help of ZK proofs.

### Application Address
Each application is identified by an address that is derived from its verifier key `app_VK` (that is itself derived from the `appVP`):
`appAddress = Com(app_VK)`

TODO: what is a verifier key, how are they computed

TODO: App is basically identified by the appVP, but as it is shielded nobody can do that. Instead, the address is derived


### Example
##### Create a application
In order to create a application, we need `AppVP`. Let's use the `TrivialValidityPredicate` (see [more](./validity-predicates.md)):
```rust
let mut app_vp = TrivialValidityPredicate::<CP> {
	input_notes,
	output_notes,
};

// transform the VP into a short form 
let desc_vp = ValidityPredicateDescription::from_vp(&mut app_vp, &vp_setup).unwrap();

let app = App::<CP>::new(desc_vp);

//app address can be used to create notes of that app;
let app_address = app.address().unwrap();
```
This example is reproducible with [this file](https://github.com/anoma/taiga/blob/main/src/doc_examples/app.rs) or with the command
```
cargo test doc_examples::app::test_app_creation
```

#### Dummy app

It is also possible to create a dummy app without VP:

```rust
let app = App::<CP>::dummy(&mut rng)
```

Using this app, we can create a [dummy note](./notes.md) of a specific app (all other fields are random):

```rust
let note = Note::<CP>::dummy_from_app(app, rng)
```

Next: [User](./users.md)