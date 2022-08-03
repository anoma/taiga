# Token

`Token` define the type of note (e.g. XAN, ETH, BTC). Each token is identified by an address `tokenAddress` (the same way as user address identifies a user) and has its own VP `tokenVP`.

### Token VP
Each token has its own VP `tokenVP` that defines the conditions on which the token can be sent/received/etc (e.g. whitelist VP that only allows using the token a specified set of users). As with other VPs, it is required that the `tokenVP` of the tokens involved in a tx evaluated to `true`.

In Taiga, VPs are shielded, so instead of showing that `tokenVP` evaluates to `true` publicly, a ZK proof is created. To make sure that `tokenVP`  evaluates to `true`, an observer can verify the proof using  a verifier key `tokenVK`:
`verify(tokenVP_proof, tokenVK) = True`

### Token Address
Each token is identified by an address that is derived from its verifier key `tokenVK`:
`tokenAddress = Com(tokenVK)`


### Example
##### Create a token
TODO: fix the `Token::new` implementation
TODO: explain the args (maybe)
TODO: mention that currently it doesn't work really
TODO: mention the `address()` maybe

```
Token::<CP>::new(token_name, 
				 &public_parameters
				 token_VP, 
				 &mut rng)
```

Or use a func: `spawn_token` from `taiga/src/tests.rs` for dummy tokens with trivial VPs

```
let t = spawn_token::<CP>(token_name)
```

And create a note of token `T` later (see [here]() to learn more about notes):
```
let note = Note::<CP>::new(
user.address(),
t.address(),
value,
...
)
```

TODO: describe what else you can do with notes (if anything)