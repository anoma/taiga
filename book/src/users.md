# User

`User` in Taiga can own, send and receive notes. Each user has an **address** that identifies them, **validity predicates** that authorize their actions, and **keys** that are used to derive parameters.

### Validity predicates
Each user has validity predicates that authorize spending and receiving notes. Validity predicates that authorize sending notes are called `sendVP`, and validity predicates that authorize receiving notes are called `recvVP`.

These VP check that input and output notes of the tx satisfy certain constraints. When a user wants to spend a note, the satisfaction of their `sendVP` is required. Similarly, to receive a note, user's `recvVP` must be satisfied.

As VPs are shielded in Taiga, instead of showing that the VPs of the user evaluate to true publicly, ZK proofs are created. An observer can verify these proofs (using the verifier key).

### User keys
Each user has a set of keys that allows to authorize various actions or generate parameters. One of such keys is a nullifier key `nk` used to compute [note nullifiers](./notes.md) that are necessary to spend notes.

### User address

Each user has an address that allows others to send assets to the user. Address is derived from user's `sendVP`, `recvVP`, and `nk`.

### Example

Alice is a user of Taiga with validity predicates defined as follows:
* `send_VP` is a check on the amount of her spent: she does not want to send more than 3XAN at a time.
* `recv_VP` is a check on the amount she receives: she does not want to receive notes of less than 0.1XAN.

```rust
    ...
    // compose the VPs with the methods defined earlier;
    // check ../../doc_examples/users.rs to see the defined methods;
    let mut send_vp = SendVP::<CP>::new(send_input_notes, send_output_notes);
    let mut recv_vp = ReceiveVP::<CP>::new(receive_input_notes, receive_output_notes);

    //transform VPs into a different form
    let desc_vp_send = ValidityPredicateDescription::from_vp(&mut send_vp, &vp_setup).unwrap();
    let desc_vp_recv = ValidityPredicateDescription::from_vp(&mut receive_vp, &vp_setup).unwrap();

    let alice = User::<CP>::new(
        desc_vp_send, //sendVP
        desc_vp_recv, //recvVP
        NullifierDerivingKey::<Fr>::rand(&mut rng), //nullifier key
    );

    // compute the address;
    // it can be used to send notes to Alice;
    let _alice_addr = alice.address().unwrap();
```

This example is reproducible with [this file](../../src/doc_examples/user.rs) or with the command

`cargo test doc_examples::user::test_token_creation`

Next: [Note](./notes.md)