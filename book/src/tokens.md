# Tokens

In Anoma, each token defines its own rules for transactions involving it. Rules are set in a validity predicate `Token_VP`, providing a set of constraints that needs to hold in regards to the token involved in a transaction before a note can be spent or created.

The verification a `Token_VP` proof requires a verifier key `Token_VK`: Users check that `Verify(Token_π, Token_VK)` returns `True`.

In order to bind this verification to the actual note token type, we need an identification of the token. The address of a token is a commitment to its verifying key: `Token_Address = Com(Token_VK)`. Binding `Token_VK` to the token type of a note corresponds to opening the address commitment.

### Example.
We consider the token XAN, whose `Token_VP` is a white list of allowed sending users [Alice, Bob and Charlie]. Suppose that Alice has a note of 1XAN. The note has a token type (or address) which is a commitment to the `XAN_VK`. When Alice wants to spend her note, XAN produces a proof `π` corresponding to the check that Alice is in the white list, and users of Taiga can check that:
* `Verify(π, XAN_VK)` is true,
* `XAN_VK` opens the Alice's note token address.

In practice, this second step will be done using another ZK proof, and Alice simply verify two ZK proofs.
For privacy, we will see that additional proofs are required.


### Specification of the token address.
The token address encodes the token validity predicate verifier key.
```
Token_Address = Com_r(Com_q(Token_VK))
```
The VK is committed into $\mathbb F_q$ and then $\mathbb F_r$.
* The inner commitment is used for privacy concerns (see the blinding section),
* The outer commitment lets us map `Token_Address` in $\mathbb F_r$ in order to simplify circuits.

