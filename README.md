# Taiga

Taiga is a framework for generalized shielded state transitions. This repository contains the implementation of Taiga in Rust.

⚠️ Taiga is WIP and cannot be used in production yet ⚠️

![Taiga at the bottom, as a foundation for Taiga applications, and their state is stored in Notes.](./book/src/images/Intro_UTXO.png)

## Taiga in 500 Words

Taiga is a state transition protocol that allows applications built on top of it to enjoy the advantages of fully shielded multi-party state transitions (hiding the application type, the data associated with it, involved parties, etc.) without giving up the application complexity. Although an independent project, Taiga is intended to be at the heart of Anoma. Conceptually, Taiga can be seen as an operating system for execution of Anoma programs. In practice, Taiga is a set of APIs for creating notes, intents, transactions – for both shielded and transparent execution; creating and verifying transaction validity proofs; computing the state changes produced by transactions; de-/serializing all of the above.

A [Note](./book/src/notes.md) represents an Anoma resource in Taiga. Notes are immutable and have a "denomination" and a non-negative value, among other fields. Every note has a set (partially determined by the note's denomination) of executable programs (often referred to as [Validity Predicates](./book/src/validity-predicates.md) or VPs) associated with it. Taiga programs result in a state change, which includes a list of invalidated (or "nullified") notes and a list of newly created notes. Any existing note being input into a program gets invalidated. Invalidating a note means revealing its nullifier, a secret value bound to the note. Note ownership is determined by knowledge of the nullifier plus arbitrary logic in a VP associated with the note. Creating a note means computing its commitment (a hash), and adding it to a global merkle tree of commitments. The global state of Anoma is a hashset of note nullifiers and a commitment tree.

Taiga transactions consist of valid partial transactions. Every partial transaction consists of exactly two input notes and two output notes. Output notes are crafted by the creator of the partial transaction. If a transaction gets executed, its output notes are "created": added to the merkle tree. A Partial transaction is considered valid if all programs (VPs) associated with the notes comprising it are valid (result in `true`). Every VP in a partial transaction can read any field of any note in it. If we don't need all 4 note slots in a partial transaction, we can use "ephemeral" notes to fill the empty slots: they are same as real notes, but have the `is_merkle_checked` flag set to `false`. Ephemeral notes can also be used to describe the user intent by attaching an intent VP to it. Intent VP can describe arbitrarily complex logic of a valid state change: unless it is satisfied, the whole partial transaction would not be valid and therefore can't be part of a valid transaction.

Taiga transaction is valid if *1)* all contained partial transactions are valid; and *2)* the transaction is balanced: for every note denomination, the sum of values of all input notes of that denomination is equal to the sum of all output notes of the same denomination. A single partial transaction can be a valid transaction if it is balanced.

To achieve shielded properties, Taiga uses zero-knowledge proof system [Halo2](https://zcash.github.io/halo2/) to hide the sensitive information about the state transitions (application types, parties involved, etc). Transactions of different applications are indistinguishable from one another and all applications benefit from the shared shielded pool of transactions.

## Features

* Support for arbitrary *atomic* multi-party state transitions
* *Data* and *function privacy*: to a third-party observer, all transactions look the same, no matter what applications are involved
* *Matchmaking* is taken care of: with the help of *intent applications* and *solvers* finding counterparties becomes easy
* In addition to shielded execution, Taiga also implements *transparent* execution. Assets can be moved between the transparent and shielded pool, and applications may support both types of state transitions
* Performance benefits from using PLONK arithmetization (including lookups)

## Taiga Specs

* [Applications](./book/src/app.md)
* [Notes](./book/src/notes.md)
* [Validity predicates](./book/src/validity-predicates.md)
* [The Action circuit](./book/src/action.md)
* [Execution model](./book/src/exec.md)
  * [Intent Application](./book/src/intent.md)
  * [Examples](./book/src/exec_examples.md)
* [Performance](./book/src/performance.md)

or run the Taiga book:

```plaintext
cd book
mdbook serve --open
```

## Examples of Taiga Transactions

### Split the Note

Let's assume we have a note representing 1 ETH, and we want to give 0.7 ETH to a friend. To do so, we would first need to split the note into two smaller notes. Let's start constructing a partial transaction! We have a 1 ETH note, and we want a 0.7 ETH note:

```plaintext
Inputs:  [ 1 ETH ] [ ]
Outputs: [0.7 ETH] [ ]
```

We would probably want to get the change too:

```plaintext
Inputs:  [ 1 ETH ] [ ]
Outputs: [0.7 ETH] [0.3 ETH]
```

This is not a valid partial transaction because it doesn't have two inputs. We can use a padding note (let's mark padding notes using `^` symbol):

```plaintext
Inputs:  [ 1 ETH ] [0 PAD^ ]
Outputs: [0.7 ETH] [0.3 ETH]
```

Padding notes may have a non-zero value, but in this case, the value is zero, thus it doesn't contribute to balancing the transaction. Sum of input notes in this partial transaction is 1 ETH; sum of outputs is also 1 ETH. This single partial transaction is balanced, and thus is also a valid full transaction. We, of course, assume, that all VPs associated with the notes involved result in `true`.
