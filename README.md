# Taiga

Taiga is a framework for generalized shielded state transitions. This repository contains the implementation of Taiga in Rust. It is a WIP project and cannot be used in production yet.

## Specs

- [How Taiga works (with code examples)](./book/src/SUMMARY.md)
- [Cryptographic details of Taiga](./book/src/spec.md)
- [Current performance details](./book/src/conclusion.md)

### Proving system

Currently we use these parameters to generate proofs:

|||
|-|-|
|Proving system|ZK-garage PLONK|
|Inner Curve|`ed_on_bls12_381_new`|
|Main Curve |`bls12_381_new`|
|Outer Curve|`bw6_764_new`|

Note that the current choice is not final and might change. 
    
## How to run
#### The Taiga book
To generate [the Taiga book](./book/src/SUMMARY.md), run:
```
cd book
mdbook serve --open
```

#### Validity predicate examples

We provide [several VP examples](./src/circuit/vp_examples/). To generate VP example proofs and verify them, run:
```
cargo test vp_example --release
```

## Things yet to implement
* Blake2 hash circuits and all of the proofs that use blake2s
* Proper note encryption
* Proper blinding algorithm

