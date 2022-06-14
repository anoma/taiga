# Introduction


## Background

### Private ledgers

### Decentralised exchanges

A DEX is a ledger-based application that enables users to trade digital assets without giving up custody of these assets to a third party.

An intent-based DEX maintains an index, which is a table where makers publish their intention to
trade (say, a particular asset pair) without committing any assets. A taker interested in a maker’s intention
to trade can directly communicate with the maker to agree on terms. They can jointly produce a transaction
for the trade, to be broadcast for on-chain processing.

### ZEXE

Decentralised exchanges with privacy guarantees without requiring users to give up custody of their assets were studied on the [Zexe paper](https://eprint.iacr.org/2018/962.pdf).

Both privacy and function agnostic.

It's a framework, not an instance. Not specific in the implementation.

## Motivation

TODO: What are the limitations of Zexe or Zcash?

TODO: What use cases are not possible in Zexe but they are in Taiga?

TODO: How is programmability in Taiga different from Zexe?



## What is Taiga?

Taiga is a shielded protocol for bartering on Anoma, leveraging the value of validity predicates as a means to avoid race conditions due to decentralised ledgers, extending the functionality of transparent Anoma, and characterized by the goals:

* Native support for a broad range of asset types, including NFTs
* Transactions are authorized by arbitrary user-defined validity predicate circuits
* Validity predicates authorize both sending and receiving of assets, by the sender's, recipient's, and token's VPs
* Support for building complex matchmaking and private bartering transactions among multiple parties
* Full zero-knowledge privacy, including of asset type and VP circuits
* Performance benefits from using PLONK arithmetization, including lookups
* Potential for scalability via recursion or composition, or to remove requirement for trusted setup.

A block in the underlying chain contains many shielded transactions. Taiga maintains a state and needs to process transactions. A transaction consists of a set of input and output notes and a set of actions. 
- A note encodes a value $v$ of a specific token can be spent by a certain owner of the token. A note contains pointers (addresses) to a token and to a user.
- An action is a circuit that verifies a note can be spent, that is, the conditions defined in the user and token validity predicates are met and the note was not previously spent.

The address of a token or a user consists of a commitment of the token validity predicate or the user validity predicate, respectively. That is, a token or user address is uniquely identified by the rules of the underlying validity predicate.


### Transparent Anoma
### Validity Predicate Model

No dependencies


## Related work

### Zexe

In Zexe, the model of how the blockchains are programmed are different. (?)

Their motivation is: "How do you get smart contract based programmability in something like ZCash?"



### Penumbra

### Bilateral swaps (Aztec)

### Orchard

Privacy but not function agnostic (there is only one function).