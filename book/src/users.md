# Users of Taiga

## Sending and receiving VPs

The most interesting data concerning the users are their VPs.
Each users owns one sending and one receiving validity predicate corresponding to his rules for the transactions.

As an example, Alice could set:
* Sending VP: "do not send more than 3XAN",
* Receiving VP: "do not accept transactions from my ex-boyfriend".

When Alice wants to send a note, she computes a proof $π_\text{send}$ for her sending VP, together with $\text{vk}_\text{send}$ so that someone can verify it. We bind this verifying key to her identity using a commitment. Alice will open the commitment with this $\text{vk}$ in order to prove that she provided the right verifying key.

## User address

A user address is a commitment to the sending and receiving verifying keys. By opening the address, a user binds the provided verifying key to her identity. For privacy concern, we also use a ZK proof for opening the address.

In our previous example:
* Alice computes a proof $π_\text{send}$ and the corresponding verifying key $\text{vk}_\text{send}$.
* Alice computes a proof that $\text{vk}_\text{send}$ opens her public address.

## Nullifier and nullifier key

Once a note is spent, it is disable using a nullifier in the same way as in Orchard (we detail the nullifier computation in the [note section](./notes.md)). Each users owns a nullifier key in order to disable his spent notes. In the same way as the sending and receiving VPs, the nullifier key needs to be binded to the user identity when a note is sent, so we include this key to the (sending part of the) address definition.

## Final address description

A user has a sending VP and a receiving VP, and a nullifier. The user address is split as:
```
SendingCommitment = Com(SendVP, nk)
ReceivingCommitment = Com(RecVP)
UserAddress = Com(SendingCommitment, ReceivingCommitment)
```
