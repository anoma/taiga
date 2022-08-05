# Taiga

Taiga is a framework for generalized shielded state transitions. This repository contains the implementation of Taiga in Rust. It is a WIP project and cannot be used in production yet.

## Specifications

- [How Taiga works (with code examples)](./book/src/SUMMARY.md)
- [Cryptographic details of Taiga](./book/src/spec.md)
- [Current performance details](./book/src/conclusion.md)
- Choice of ZK-proof implementation. Currently, we use the [PLONK](https://github.com/ZK-Garage/plonk) implementation of [ZK-Garage](https://github.com/ZK-Garage/). The current choice of proof system is not final and might change, as well as the curves we chose:
    * The main curve is `bls12_381_new`, a different curve from the well-known `bls12_381`. Poseidon hash circuits are small for the base field and the scalar field of this curve.
    * The inner curve is `ed_on_bls12_381_new`. Its base field is the main curve scalar field and it has a small degree endomorphism enabling faster scalar multiplications compared to `ed_on_bls12_381`.
    * The outer curve is `bw6_764_new`. Its scalar field is the base field of the main curve.

    
## How to run

### The Taiga book

To generate the Taiga [book](./book/src/SUMMARY.md), run:
```
cd book
mdbook serve --open
```

### Validity predicate examples

We provide [several VP examples](./src/circuit/vp_examples/). To generate VP example proofs and verify them, run:
```
cargo test vp_example --release
```

## Things yet to implement

* Blake2 hash circuits and all of the proofs that use blake2s
* The main curve base field Poseidon hash circuit
* Proper note encryption
* Proper blinding algorithm

