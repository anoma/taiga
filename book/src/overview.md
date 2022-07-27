# Overview

## Motivation

Private decentralised exchanges enable users to trade digital assets without giving up custody of these assets to a third party. Prior work focused solely on the exchange of tokens (Penumbra, Aztec bilateral swaps), or left the details of implementing arbitrary bartering outside the scope of their work (Zexe). Taiga provides general programmability for private bartering, thus enabling the surge of applications such as subscriptions or content-based bartering (e.g. trade NFTs based on the qualitative properties of the NFT). Unlike previous work (Zexe, ZCash Sapling), Taiga is designed from the ground up using the state of the art in proving systems, Plonk, which affects how private computation is achieved.


## Introduction

Taiga is a shielded protocol for bartering on Anoma, leveraging the value of validity predicates as a means to avoid race conditions due to decentralised ledgers, extending the functionality of transparent Anoma, and characterized by the goals:

* Native support for a broad range of asset types, including NFTs
* Transactions are authorized by arbitrary user-defined validity predicate circuits
* Validity predicates authorize both sending and receiving of assets, by the sender's, recipient's, and token's VPs
* Support for building complex matchmaking and private bartering transactions among multiple parties
* Full zero-knowledge privacy, including of asset type and VP circuits
* Performance benefits from using PLONK arithmetization, including lookups
* Potential for scalability via recursion or composition, or to remove requirement for trusted setup.

## Terminology

A *block* in the underlying chain contains many shielded transactions. Taiga maintains a state and processes transactions. A *transaction* consists of a set of input and output notes and a set of actions. 
- A *note* encodes a value $v$ of a specific token can be spent by a certain owner of the token. A note contains pointers (i.e. addresses) to a token and to a user.
- An *action* is a circuit that verifies a note can be spent, that is, the conditions defined in the user and token validity predicates are met and the note was not previously spent.

The *address* of a token or a user consists of a commitment of the token validity predicate or the user validity predicate, respectively. That is, a token or user address is uniquely identified by the rules of the underlying validity predicate.

## Validity Predicate Model

*Validity predicates* can be seen as a set of rules (i.e. a circuit) that assess the truth of a statement. They are used to determine whether a state transition is valid or not. During the execution phase of a transaction, both the validity predicates associated with the sender/receiver and the token involved will be called. Each triggered validity predicate will independently evaluate this state change, which will either be accepted or rejected based on the evaluation. As validity predicates are very flexible, they can be tailored to handle a variety of use cases.

As validity predicates are stateless, they can be parallelized.

## Related work

### ZEXE

Decentralised exchanges with privacy guarantees without requiring users to give up custody of their assets were first studied in the [Zexe paper](https://eprint.iacr.org/2018/962.pdf).

Zexe uses Groth16 as its underlying proving system, whereas Taiga uses Plonk. The choice of a proving system determines the design of private computation in the protocol.

Zexe describes how simple private contracts can be implemented, but leaves as an open problem how to implement full generality.

### Penumbra

### Bilateral swaps (Aztec)

### ZCash Orchard

Privacy but not function agnostic (there is only one function).