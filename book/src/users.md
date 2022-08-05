# Users of Taiga

Similarly to the token case, users have associated validity predicates for sending and receiving notes, called $Send_{VP}$ and $Rec_{VP}$, respectively. In the same way as for $Token_{VP}$, a proof $\pi$ is verified against a $Send_{VK}$ (or $Rec_{VK}$) and this verifier key needs to be binded to the owner of the note. 

Spending a note also requires nullifying the note so that it cannot be double-spent. We use the same construction as Orchard, where a nullifier is derived from a nullifier key. Each user has a nullifier key that also needs to be binded to the note sender address.

In consequence, the user address is split into:
* A commitment to $Send_{VK}$ and the nullifier key,
* A commitment to $Rec_{VK}$.
The final address is an outer commitment to these two inner commitments: 

    $Address_{user}$ = Com(Com($Send_{VK}$, $User_{NK}$, Com($Rec_{VK}$)).

### Example

Alice is a user of Taiga and defined her two validity predicates:
* $Send_{VP}$ is a check on the amount of her spent: she does not want to send more than 3XAN at a time.
* $Rec_{VP}$ is a check on the amount she received: she does not want to receive notes of less than 0.1XAN.

When she sends a note of $2$ XAN, she creates a proof $Send_π$ that can be verified against $Send_{VK}$, computes the nullifier of the spent note using $Alice_{NK}$, and a binding proof that $Send_{VK}$ and $Alice_{NK}$ open the spent note owner (Alice) address.

```rust
    let mut send_vp = SendVP::<CP>::new(send_input_notes, send_output_notes);
    let mut receive_vp = ReceiveVP::<CP>::new(receive_input_notes, receive_output_notes);

    let desc_vp_send = ValidityPredicateDescription::from_vp(&mut send_vp, &vp_setup).unwrap();
    let desc_vp_recv = ValidityPredicateDescription::from_vp(&mut receive_vp, &vp_setup).unwrap();

    let alice = User::<CP>::new(
        desc_vp_send,
        desc_vp_recv,
        NullifierDerivingKey::<Fr>::rand(&mut rng),
    );
```
This example is reproducible with [this file](../../src/doc_examples/user.rs) or with the command
```
cargo test doc_examples::user::test_token_creation
```


### Specification of the user address

The user address encodes the sending and receiving validity predicate verifier keys and the nullifier key.

$Address_{User} = Com_r(Com_r(Com_q(Send_{VK}) || User_{NK}) || Com_q(Rec_{VK}))$

* Sending and receiving verifier keys are commited into $\mathbb F_q$ for privacy and efficiency concerns.
* The commitment to $Send_{VK}$ is committed into $\mathbb F_r$ together with the nullifier key in order to bind the nullifier computation with the spent note owner address.
* The outer commitment binds the spent note user address with the verifying keys used for $Send_{π}$ and $Rec_{π}$.
