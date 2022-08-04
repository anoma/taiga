# Action VP

We detail here how the action circuit works. It corresponds to the verification for a note to be spent, and another to be created.

Recall that a note has a field `owner_address` that identifies the owner of the note using `User.address()`, and `token_address` that is computed using `Token.address()`. Moreover,
```rust
User.address(self) = com_r( com_r(com_q(self.desc_send,0) || self.nk ) || com_q(self.desc_recv,0), self.rcm_address)
Token.address(self) = com_r(com_q(self.desc_vp, 0), 0)
```

There are different steps involved in the spent and creation of notes.

## Fresh commits

The sender computes some fresh commitments for `Sender.send_vp` and `Receiver.recv_vp`.
These commitments will be useful for the Action circuit *and* the blinding circuit.
A fresh commit is of the form `com(com_q(desc_vp, 0), rand)` where `rand` is a fresh random integer.
As we will need these fresh commitments for both the Action and the blinding circuits, we need `Com` to be efficient over `CurveScalarField` *and* `CurveBaseField`.


## VP proofs

The sender produces three proofs for the three corresponding VPs `Sender.send_vp`, `Receiver.recv_vp` and `Token.vp`.
For the two first VP, he computes a blinding version of the circuit. These proofs can be verified with the `verifier` field of `ValidityPredicate`.
The three VPs are defined over `CurveScalarField`, while the `verifier` blindings are defined over `CurveBaseField`.


## Note check

The sender proves that `OldNote.commitment` exists in the Merkle tree of note commitments.
He also proves that he computed the nullifier of `OldNote` using his nullifier key `nk`.
Finally, he proves that he computed the new commitment added to the Merkle tree of note commitments.


## Binding with addresses

The sender proves that the three VPs above corresponds to the addresses of the notes. More precisely:

* `Sender.send_vp` and `Sender.nk` are the ones used for `OldNote.owner_address`,
* `Receiver.recv_vp` is the one used for `NewNote.owner_address`,
* `Token.vp` is the one used for `OldNote.token_address`,
* `Token.vp` is the one used for `NewNote.token_address` (when the new note has the same token type).

These circuits are also done over `CurveScalarField` in order to match the circuit field of the VP proofs.


## Binding with fresh commits

The sender proves that `Sender.send_vp` and `Receiver.recv_vp` used above correspond to the fresh commits.
The fresh commits needs to be open over `CurveScalarField` in order to match the circuit field of the VP proofs.


## Proof of blinding

The sender proves that the ValidityPredicates `Sender.send_vp` and `Receiver.recv_vp` are blinded correctly using `_blind_rand` into `verifier`,
and that it corresponds to the fresh commits of step 1. This is a circuit over `CurveBaseField`, where the blinding takes place.
Thus, we need to open the fresh commits over `CurveBaseField`.
