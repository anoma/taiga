
## Motivation

Private decentralised exchanges let users trade digital assets without giving up the custody of these assets to a third party. Previous works in this field were either solely focused on exchanging tokens (e.g. Penumbra, Aztec bilateral swaps), or left the implementation details (many of which significantly impact the resulting system properties) outside the scope of their work (e.g. Zexe). Taiga aims to resolve these problems.


## State model in Taiga

Unlike transparent Anoma, which operates on an account model, Taiga is based on a UTXO model. In the account model, each account has associated state stored in a database, and updated according to that account's VP. In the UTXO model, however, the state is stored in append-only sets of *note commitments* and revealed *nullifiers*. Each note has exactly one associated nullifier, and the current state of the Taiga is the subset of notes whose nullifiers are not yet revealed, called unspent notes. The Action/Execute circuit, together with the transaction verifier, ensure that the Taiga state is consistent.

##-

VPs take the current and next proposed state as input and check if the state transition is allowed.

##-

Informally, transactions take a private subset of unspent notes from the Taiga note set, publicly reveal their nullifiers, and reveal a new set of note commitments to add to the Taiga note set. The Action/Execute circuit verifies consistency of this state transition, but does not check directly its validity. Instead, the validity predicate circuits must check the validity of the state transition. The following VPs are called:

##### ----------

The VP configuration includes the following "gates" in the PLONK configuration:
* Field addition/multiplication
* Elliptic curve addition and scalar multiplication
* Poseidon hash

#### Partial transactions' details

||spent notes|created notes|Apps|VP proofs|total balance (accumulated)|
|-|-|-|-|-|-|
|ptx #2.1 (Alice)|star NFT|Alice intent note|star NFT app, intent app|star NFT appVP, intent appVP, Alice star NFT userVP(3)|-[star NFT] + [Alice intent note]|
|ptx #2.2 (Bob)|blue dolphin NFT|Bob intent note|blue dolphin NFT, intent app|blue dolphin NFT appVP, intent appVP, Bob blue dolphin NFT userVP(3)|-[star NFT] - [blue dolphin NFT] + [Bob intent note] + [Alice intent note]
|ptx #3.1 (Solver #1)|[Alice intent note]|[blue dolphin NFT for Alice]|blue dolphin NFT app, intent app|blue dolphin NFT appVP, intent appVP, Alice intent userVP|-[star NFT] + [Bob intent note]|
|ptx #2.3 (Charlie)|tree NFT|Charlie intent note|tree NFT app, intent app||-[star NFT] - [tree NFT] + [Bob intent note] + [Charlie intent note]|
|ptx #4.1 (Solver #2)|[Bob intent note], [Charlie intent note]|[star NFT for Charlie], [tree NFT for Bob]|intent app, star NFT app, tree NFT app||0|
star NFT appVP, intent appVP, Alice star NFT userVP, Alice intent userVP (4)
