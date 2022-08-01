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
