# Taiga

This repository provides a starting point for
[Anoma](https://anoma.network/) Taiga.
We try to follow the (work-in-progress) [specification](https://hackmd.io/IV6AZgoRQWC91D4Z4AG6jQ?view) as much as possible.
Currently, we are not able to produce all the proofs needed for Taiga (the main blocker is the implementation of hash function circuits), but we can already implement lots of structures with simple circuits.

## Warning
The implementation is probably not secure nor efficient:
* The `hash-to-field` function in [`src/lib.rs`](https://github.com/heliaxdev/taiga/blob/main/src/lib.rs) is probably not the right way for hashing into a field.
* The `hash-to-curve` algorithm used in the `commitment` method in [`src/note.rs`](https://github.com/heliaxdev/taiga/blob/main/src/note.rs) is a naive hash that must not be used in a real-world implementation.
* The nullifier computed in the `spend` method in [`src/user.rs`](https://github.com/heliaxdev/taiga/blob/main/src/user.rs) should be replaced by an implementation as specified by Zcash.
* The El Gamal encryption scheme is based on the first option of [this post](https://crypto.stackexchange.com/questions/14955/mapping-of-message-onto-elliptic-curve-and-reverse-it?rq=1).
* There are lots of other security/efficiency issues to be solved in this implementation.

## Code structure
The code is organized as follows:
```
.
├── action.rs
├── circuit
│   ├── blinding_circuit.rs
│   ├── circuit_parameters.rs
│   └── validity_predicate.rs
├── circuit.rs
├── el_gamal.rs
├── lib.rs
├── note.rs
├── tests.rs
├── token.rs
├── transaction.rs
└── user.rs
```

### Circuit
The circuit directory contains some structures related to the validity predicates and circuits in general.

#### Circuit Parameters
As we use PLONK, we are flexible on the choice of the polynomial commitment scheme. We can use:
* Either a pairing-based polynomial commitment scheme, for example the BLS12-377 curve and an inner curve like `ed_on_bls12_377`,
* Either a discrete-logarithm polynomial commitment scheme, for example the Vesta curve and its inner curve Pallas.

This trait lets us access to the two curves (called `MainCurve` and `InnerCurve`), and their corresponding prime fields: `CurveBaseField`, `CurveScalarField` and `InnerCurveScalarField` (recall that the base field of `InnerCurve` is by definition the scalar field of `MainCurve`).

#### Validity predicate
This corresponds to the circuits defined over `CurveScalarField`, namely the `send`, `recv` and `token` VPs. The Action circuit is also defined over this field but does not require the blinding property.

### El Gamal encryption
We encrypt the notes using the El Gamal encryption. This is a classical algorithm we use with the `InnerCurve`, so that we can build an Action circuit (later) for integrity check proofs.
    
### User

Users are binded to private and public information. Each user defines rules for sending and receiving tokens. These are represented using circuits / validity predicates (VP). Checking these rules (i.e. verifying a VP proof) requires only a precomputation called `preprocessing_{sending/receiving}_vp` that can be blinded using random integers, leading to `blinded_preprocessing_{sending/receiving}_vp`. Each user has a `nullifier_key`, useful for "disabling a note that has been spent (see below what is a note). Users are identified using an address. It is computed by hashing into two fields, using a `rcm_addr` random integer and the `nullifier_key`.

### Note

When Alice wants to send 1XAN to Bob, it means that Alice has the notes of total amount of at least 1XAN that she received before. In a note, we can identify its owner (with his address defined above), a token (see below) and a value (`1` if Alice wants to send 1XAN). Notes are also hashed so they have a field `rcm` (a random integer), and a nullifier in order to know whether if the note has been spent. Once Alice spend her note, we add its nullifier in a database of "spent nullifiers" so that she cannot use it again. When a note is created, its commitment is added to the note commitment merkle tree and it is (together with the encrypted version of the note) added to the note-commitment-and-encrypted-note list.

### Token

A token has its proper rules. For example, we can imagine that XAN can be used only to buy sushis. This is stored into a circuit/VP. As for user VPs, a preprocessing `desc_token_vp` is computed in order to check that the rules are respected. The token is identified with an address. It is a hash into a field of the data related to the token (`desc_token_vp`) but also requires a random integer `rcm`.

### Commands
* Generating the (wip) book:
```
cd book
mdbook serve --open
```

* Example of sending 1XAN:
```
cargo test test_send_kzg
cargo test test_send_ipa
```
* Example of checking proofs:
```
cargo test  test_check_proofs_kzg
```
* Split a note into two notes:
```
cargo test test_split_note_for_different_curves
```
