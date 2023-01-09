
## Motivation

Private decentralised exchanges let users trade digital assets without giving up the custody of these assets to a third party. Previous works in this field were either solely focused on exchanging tokens (e.g. Penumbra, Aztec bilateral swaps), or left the implementation details (many of which significantly impact the resulting system properties) outside the scope of their work (e.g. Zexe). Taiga aims to resolve these problems.


#### State model in Taiga

Unlike transparent Anoma, which operates on an account model, Taiga is based on a UTXO model. In the account model, each account has associated state stored in a database, and updated according to that account's VP. In the UTXO model, however, the state is stored in append-only sets of *note commitments* and revealed *nullifiers*. Each note has exactly one associated nullifier, and the current state of the Taiga is the subset of notes whose nullifiers are not yet revealed, called unspent notes. The Action/Execute circuit, together with the transaction verifier, ensure that the Taiga state is consistent.

##-

VPs take the current and next proposed state as input and check if the state transition is allowed.

##-

Informally, transactions take a private subset of unspent notes from the Taiga note set, publicly reveal their nullifiers, and reveal a new set of note commitments to add to the Taiga note set. The Action/Execute circuit verifies consistency of this state transition, but does not check directly its validity. Instead, the validity predicate circuits must check the validity of the state transition. The following VPs are called:
