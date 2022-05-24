# Nullifier computation
Our design follows the Orchard specification: `psi` is an element of `InnerCurveScalarField` and the note commitment is a point of `InnerCurve`.
The nullifier is also an element of `InnerCurve` and the circuit for nullifier integrity computes a scalar and then a scalar multiplication.
This should be split into two circuits (over the scalar and the base fields of `InnerCurve`) but it is done as in Orchard: the scalar part is also done over `InnerCurveBaseField=CurveScalarField`.

# Validity predicates commitment
Taiga uses commitment to circuit precomputations in order to bind a (sender, receiver, token) validity predicate to a user or a token.
These precomputations are first packed in order to be reduced to a smaller (and fixed) size element. Then, the binding are done using this hash and it is open only once.

What is the argument for all of them for opening into `CurveScalarField` or `CurveBaseField`? For one of them, it is binded to the randomization circuit which is done over `CurveBaseField`.

# Token address
The address of a token is `Com_q(H(token_vp), rcm_token_addr)`. This commitment is open over `Fq` but we should denote it `CurveScalarField`. The `token_vp` is a circuit defined over `CurveScalarField`, but I don't really understand why we need to define the commitment over the *same* field?

# User address
The address of a user is computed using a hash into `CurveScalarField`. Same question as for token?

# Possible hash function implementations
We need to figure out all the possible `hash_to_curve` and `hash_to_field` functions, in terms of security properties, and existing implementations.
Some of them may be available for particular curves or fields.
I have in mind:
* For `hash_to_field`: [Poseidon](https://www.poseidon-hash.info/), [reinforced concrete](https://eprint.iacr.org/2021/1038.pdf), etc.
* For `hash_to_curve`: [Pedersen hash]() (but it has particular security properties, see [here](https://github.com/zcash/zcash/issues/2234#issuecomment-315726396)), the implementation of arkworks (not sure if it is implemented for `ed_on_bls12_377`).