# Taiga

This repository provides a starting point for
[Anoma](https://anoma.network/) Taiga, specified [here](https://github.com/anoma/taiga/blob/main/book/src/spec.md).

## Warning
* Currently, we are not able to produce all the proofs needed for Taiga (the main blocker is the implementation of the Blake2 hash circuits), but the structure and examples of circuits are already available.
* For now, we didn't implement the note encryption for our code demonstration.
* Our blinding algorithm is not fully blinding. We are looking for a new way of blinding.

## Validity predicate examples
We provide several examples of validity predicates (see `src/circuit/vp_examples/`):
* Balance. This VP checks that all the input and output notes are of the same token types, and that the sum of the input note values equals the sum of the output note values. Note that this VP might be included in all transactions and is maybe not a "custom" VP, but can also be a token VP.
* Field addition. A useless but simple VP that checks that two private inputs `a` and `b` satisfy `a+b == c` for a public value `c`.
* White list senders. Given a list of user addresses, the VP checks that the input note owners are in the list. This can be used as a receiver VP.
* White list tokens. The VP checks that the input and output notes are of a token type provided in a list. This can be used as a sender or receiver VP.

## Circuit implementation
We use the ZK-garage PLONK implementation. It is flexible in the sense that we can easily change the polynomial commitment scheme, and the layer of curves (`InnerCurve -- MainCurve -- OuterCurve`). For now, we decided to use `ed_on_bls12_377 -- bls12_377 -- bw6_761` for our code demonstration. See `src/circuit/circuit_parameters.rs` for details.
    
## Structures of Taiga

### User
Users are binded to private and public information. Each user defines rules for sending and receiving tokens. These are represented using circuits / validity predicates (VP). Checking these rules (i.e. verifying a VP proof) requires only a precomputation called `preprocessing_{sending/receiving}_vp` that can be blinded using random integers, leading to `blinded_preprocessing_{sending/receiving}_vp`. Each user has a `nullifier_key`, useful for "disabling a note that has been spent in the same way as Zcash does.

### Token
A token has its proper rules. For example, we can imagine that XAN can be used only to buy sushis. This is stored into a circuit/VP. As for user VPs, a preprocessing `desc_token_vp` is computed in order to check that the rules are respected. The token is identified with an address. It is a hash into a field of the data related to the token (`desc_token_vp`) but also requires a random integer `rcm`.

### Note
Taia is based on the UTXO model, meaning that transactions are done with notes. In a note, we can identify its owner (with his address defined above), a token (see above) and a value (representing the amount of tokens). Notes are disabled using a nullifier in the same way as Zcash does, and new notes are created and committed using a hash function.


## Commands
* Generating the (wip) book:
```
cd book
mdbook serve --open
```
* Computing the validity predicate examples (proof and verification):
```
cargo test vp_example --release
```
(this takes few minutes to compile)

