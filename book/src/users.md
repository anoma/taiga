# Users of Taiga

Similarly to the token case, users have validity predicates for defining rules when sending and receiving notes. These two VPs are called `send_VP` and `recv_VP` and only one of them is used whether if a note is spent or created. In the same way as for `token_VP`, a proof `π` is verified against a `send_VK` (or `recv_VK`) and this verifier key needs to be binded to the owner of the note.

Spending a note also requires nullifying the note so that it cannot be double-spent. We use the same construction as Orchard, where a nullifier is derived from a nullifier key. Each user has a nullifier key that also needs to be binded to the note sender address.

In consequence, the user address is split into:
* A commitment to `send_VK` and the nullifier key,
* A commitment to `recv_VK`.
The final address is an outer commitment to these two inner commitments: `User_Address = Com(Com(send_VK, User_NK), Com(recv_VK))`.

### Example.

Alice is a user of Taiga and defined her two validity predicates:
* `send_VP` is a check on the amount of her spent: she does not want to send more than 3XAN at a time.
* `recv_VP` is a check on the amount she received: she does not want to receive notes of less than 0.1XAN.

When she sends a note of 2XAN, she creates a proof `Send_π` that can be verified against `send_VK`, computes the nullifier of the spent note using `Alice_NK`, and a binding proof that `send_VK` and `Alice_NK` open the spent note owner (Alice) address.

### Specification of the user address.

The user address encodes the sending and receiving validity predicate verifier keys and the nullifier key.

```
User_Address = Com_r(Com_r(Com_q(send_VK) || User_NK) || Com_q(recv_VK))
```
* Sending and receiving verifier keys are commited into $\mathbb F_q$ for privacy and efficiency concerns.
* The commitment to `send_VK` is committed into $\mathbb F_r$ together with the nullifier key in order to bind the nullifier computation with the spent note owner address.
* The outer commitment binds the spent note user address with the verifying keys used for `Send_π` and `Rec_π`.
