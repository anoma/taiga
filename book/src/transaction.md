# Transaction

## Overview
The structure `Transaction` defines all the information needed to be executed on the blockchain.
Once a transaction is executed successfully (i.e. verified), the ledger status will be transfered.
A transaction includes the proofs corresponding to the spending of input notes and the creation of output notes.

In our current implementation version, there are four input notes and four output notes in each transaction. A transaction is split into *action transfers*.

## Action Transfer
An action transfer spends an input note and creates an output note. To do so, it verifies:
* one `SendVP` proof and one `AppVP` proof corresponding to an input note,
* one `RecvVP` proof and one `AppVP` proof corresponding to an output note,
* one action proof corresponding to the integrity of the owner and app addresses of the two notes,
* that the input note already exists and is not spent,
* the output note encryption.

The details of the action transfer can be found [here](src/transaction.rs).

## Proofs of a transaction
A transaction includes several proofs for the different VPs and for the actions and the blinding proofs.
In this current implementation, we set `NUM_NOTE=4` for the number of input and output notes. Moreover, for we are interested in the `SendVP` and the `AppVP` of input notes and `RecvVP` and `AppVP` of output notes.
Therefore, a transaction includes:
* Four `AppVP` proofs corresponding to the four input note app constraints,
* Four `AppVP` proofs corresponding to the four output note app constraints.
* Four action proofs for binding the 16 first proofs of this list to the actual input and output note owner and app addresses, as described [here](action.md).

![](img/taiga_tx.png)


## How to build a transaction
Building a Taiga transaction is flexible: a transaction can be created from different [users](link) and splitted into several phases. In general, we can build a transaction as the following procedures:
1. Create `Actions`,
2. Collect all the (input and output) notes from the actions as local data for VPs,
3. Create user and app validity predicates,
4. Generate the blinding proofs,
5. Build the full transaction.
