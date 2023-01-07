# Taiga overview

## Motivation

Private decentralised exchanges enable users to trade digital assets without giving up custody of these assets to a third party. Prior work focused solely on the exchange of tokens (Penumbra, Aztec bilateral swaps), or left the details of implementing arbitrary bartering outside the scope of their work (Zexe). Taiga provides general programmability for private bartering, thus enabling the surge of applications such as subscriptions or content-based bartering (e.g. trade NFTs based on the qualitative properties of the NFT). Unlike previous work (Zexe, ZCash Sapling), Taiga is designed from the ground up using the state of the art in proving systems, Plonk, which affects how private computation is achieved.

## Introduction

Taiga is a framework for shielded state transitions, leveraging the value of validity predicates as a means to avoid race conditions due to decentralised ledgers, extending the functionality of transparent Anoma, and characterized by the goals:

* Native support for a broad range of asset types, including NFTs
* Transactions are authorized by arbitrary user-defined validity predicate circuits
* Validity predicates authorize both sending and receiving of assets, by the sender's, recipient's, and applications's VPs
* Support for building complex matchmaking and private bartering transactions among multiple parties
* Full zero-knowledge privacy, including of asset type and VP circuits
* Performance benefits from using PLONK arithmetization, including lookups
* Potential for scalability via recursion or composition, or to remove requirement for trusted setup.

Taiga is a schielded state transition system that allows custom applications to enjoy the advantages of shielded state transitions without giving up the

Taiga is a protocol enabling schielded state transitions on Anoma. 
All of the Taiga transactions share the same shielded pool which makes it even more private.
Validity predicates are a key component of Taiga and are used to enable custom requirements on the transaction.
Applications built on top of Taiga use validity predicates to dictate the rules of how to use them.
Everything in Taiga is hidden under ZKPs and transactions of different applications are indistinguishable from each other.
Partial transactions
Solvers
Intents



Next: [Validity predicates](./validity-predicates.md)