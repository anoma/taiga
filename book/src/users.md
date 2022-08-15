# User

Similarly to the token case, users have associated validity predicates for sending and receiving notes, called $VP_{Send}$ and $VP_{Rec}$, respectively. In the same way as for $VP_{Token}$, a proof $\pi$ is verified against a $VK_{Send}$ (or $VK_{Rec}$) and this verifier key needs to be binded to the owner of the note. 

### Validity predicates
Each user has validity predicates that authorize spending and receiving notes. Validity predicates that authorize sending notes are called `SendVP`, and validity predicates that authorize receiving notes are called `RecvVP`.

In consequence, the user address is split into:
* A commitment to $VK_{Send}$ and the nullifier key,
* A commitment to $VK_{Rec}$.
The final address is an outer commitment to these two inner commitments: 

    $Address_{user}$ = Com(Com($VK_{Send}$, $NK_{User}$, Com($VK_{Rec}$)).

### Example

Alice is a user of Taiga and defined her two validity predicates:
* $Send_{VP}$ is a check on the amount of her spent: she does not want to send more than 3XAN at a time.
* $VP_{Rec}$ is a check on the amount she received: she does not want to receive notes of less than 1XAN.

When she sends a note of $2$ XAN, she creates a proof $Send_π$ that can be verified against $VK_{Send}$, computes the nullifier of the spent note using $NK_{Alice}$, and a binding proof that $VK_{Send}$ and $NK_{Alice}$ open the spent note owner (Alice) address.

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

$Address_{User} = Com_r(Com_r(Com_q(VK_{Send}) || NK_{User}) || Com_q(VK_{Rec}))$

* Sending and receiving verifier keys are commited into $\mathbb F_q$ for privacy and efficiency concerns.
* The commitment to $VK_{Send}$ is committed into $\mathbb F_r$ together with the nullifier key in order to bind the nullifier computation with the spent note owner address.
* The outer commitment binds the spent note user address with the verifying keys used for $\pi_{Send}$ and $\pi_{Rec}$.
