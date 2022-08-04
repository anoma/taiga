# Token

`Token` define the type of note (e.g. XAN, ETH, BTC). Each token is identified by an address `tokenAddress` (the same way as user address identifies a user) and has its own VP `tokenVP`.

### Token VP
Each token has its own VP `tokenVP` that defines the conditions on which the token can be sent/received/etc (e.g. whitelist VP that only allows using the token a specified set of users). As with other VPs, `tokenVP` checks that input and output notes of the tx satisfy certain constraints.
It is required that the `tokenVP` of the tokens involved in a tx evaluated to `true`.

In Taiga, VPs are shielded, so instead of showing that `tokenVP` evaluates to `true` publicly, a ZK proof is created. To make sure that `tokenVP`  evaluates to `true`, an observer can verify the proof using  a verifier key `tokenVK`:

```verify(tokenVP_proof, tokenVK) = True```

### Token Address
Each token is identified by an address that is derived from its verifier key `tokenVK`:
`tokenAddress = Com(tokenVK)`


### Example
##### Create a token
In order to create a token, we need `tokenVP`. Let's use the `TrivialValidityPredicate` created in the [previous section](./validity-predicates.md):
```rust
let mut token_vp = TrivialValidityPredicate::<CP> {
	input_notes,
	output_notes,
};

// transform the VP into short form 
let desc_vp = ValidityPredicateDescription::from_vp(&mut token_vp, &vp_setup).unwrap();

let token = Token::<CP>::new(desc_vp);
let token_address = token.address().unwrap();
```
This example is reproducible with [this file](../../src/doc_examples/token.rs) or with the command
```
cargo test doc_examples::token::test_token_creation
```

#### Dummy token

It is also possible to create a dummy token without VP:

```rust
let token = Token::<CP>::dummy(&mut rng)
```

Using this token, we can create a [dummy note](./notes.md) of a specific token (all other fields are random):

```rust
let note = Note::<CP>::dummy_from_token(token, rng)
```
