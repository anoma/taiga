# Application

`App` define the type of note (e.g. XAN, ETH, BTC). Each application is identified by an address `appAddress` (the same way as user address identifies a user) and has its own VP `AppVP`.

### Application VP
Each application has its own [validity predicate](./validity-predicates.md) `TokVP` that defines the conditions on which the application can be sent/received/etc (e.g. whitelist VP that only allows using the application a specified set of users). As with other VPs, `TokVP` checks that input and output notes of the tx satisfy certain constraints.
It is required that the `TokVP` of the applications involved in a tx evaluated to `true`.

In Taiga, VPs are shielded, so instead of showing that `AppVP` evaluates to `true` publicly, a ZK proof is created. To make sure that `AppVP`  evaluates to `true`, an observer can verify the proof (using the verifier key):

```verify(TokVP_proof, app_VK) = True```

### Application Address
Each app is identified by an address that is derived from its verifier key `app_VK`:
`appAddress = Com(app_VK)`


### Example
##### Create a application
In order to create a application, we need `TokVP`. Let's use the `TrivialValidityPredicate` (see [more](./validity-predicates.md)):
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