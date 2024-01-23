## VP Examples

Let's define a trivial VP that takes spent and output notes as input, checks nothing and returns true:
```rust
pub struct TrivialValidityPredicate<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}

impl<CP: CircuitParameters> Circuit<CP::CurveScalarField, CP::InnerCurve> for TrivialValidityPredicate<CP>
{
    ...
    
    //the VP constraints are defined here
    fn gadget(
        &mut self,
        _composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        // do nothing and return Ok()
        Ok(())
    }
   ... 
}
```
Now we can compute the proof for our VP and verify it:
```rust
let mut vp = TrivialValidityPredicate::<CP> { input_notes, output_notes };

// setup of the proof system
let vp_setup = PC::setup(vp.padded_circuit_size(), None, &mut rng).unwrap();

// compute proving and verifying keys
let (pk, vk) = vp.compile::<PC>(&vp_setup).unwrap();

// generate the proof
let (proof, public_inputs) = vp.gen_proof::<PC>(&vp_setup, pk, b"Test").unwrap();

// verify the proof to make sure the VP is satisfied
let verifier_data = VerifierData::new(vk, public_inputs);
verify_proof::<Fr, P, PC>(
    &vp_setup,
    verifier_data.key,
    &proof,
    &verifier_data.pi,
    b"Test",
).unwrap();
```

You can find the full example [here](https://github.com/anoma/taiga/blob/main/taiga_zk_garage/src/doc_examples/validity_predicate.rs).

## Example of blinding proof
First, we create a blinding circuit structure including the random values used for blinding:
```rust
let mut blinding_circuit =
      BlindingCircuit::<CP>::new(&mut rng, vp_desc, &pp, vp.padded_circuit_size()).unwrap();
```
As for `SendVP`, `RecvVP` and `AppVP` proofs, we need a setup and prover/verifier keys:
```rust
let (pk_blind, vk_blind) = vp
      .compile_with_blinding::<PC>(&pp, &blinding_circuit.get_blinding())
      .unwrap();
let pp_blind = Opc::setup(blinding_circuit.padded_circuit_size(), None, &mut rng).unwrap();
```
From that, we can generate the blinding proof. Note that this is a bit expensive in practice:
```rust
let (proof, public_inputs) = blinding_circuit
      .gen_proof::<Opc>(&pp_blind, pk, b"Test")
      .unwrap();
```
From a proof, the verifier can check the public inputs against the blinded verifier key `vk_blind` (see [here](https://github.com/anoma/taiga/blob/main/src/doc_examples/blinding.rs)), and verify the proof:
```rust
let verifier_data = VerifierData::new(vk, public_inputs);
verify_proof::<Fq, OP, Opc>(
    &pp_blind,
    verifier_data.key,
    &proof,
    &verifier_data.pi,
    b"Test",
)
.unwrap();
```


#### Creating a note
TODO: add a hyperlink to the existing code
We provide an example of creation of a note from the structure we have already defined for [Application]() and [User]():
```rust
// ...
// we use the code of the previous sections
// ...

// app and user
let desc_vp_app = ValidityPredicateDescription::from_vp(&mut vp, &vp_setup).unwrap();
let desc_vp_send = desc_vp_app.clone();
let desc_vp_recv = desc_vp_send.clone();

let app = App::<CP>::new(desc_vp_app);
let alice = User::<CP>::new(
	desc_vp_send,
	desc_vp_recv,
	NullifierDerivingKey::<Fr>::rand(&mut rng),
);
// note
let nf = Nullifier::<CP>::new(Fr::rand(&mut rng));
let note = Note::<CP>::new(alice, app, 12, nf, Fr::rand(&mut rng), Fr::rand(&mut rng));

let _note_commitment = note.commitment();
```
This example can be run from [this file](https://github.com/anoma/taiga/blob/main/src/doc_examples/note.rs) with the command:
```
cargo test doc_examples::note::test_note_creation
```
#### Dummy note

```rust
let spend_note = Note::<CP>::dummy(&mut rng);
```

## How to build a tx

The following example build a transaction following this procedure:
```rust
// Construct action infos
let mut actions: Vec<(Action<CP>, ActionCircuit<CP>)> = (0..NUM_TX_SLICE)
    .map(|_| {
        let action_info = ActionInfo::<CP>::dummy(&mut rng);
        action_info.build(&mut rng).unwrap()
    })
    .collect();
// Generate action proofs
let action_slices: Vec<ActionSlice<CP>> = actions
    .iter_mut()
    .map(|action| ActionSlice::<CP>::build(action.0, &mut action.1).unwrap())
    .collect();
// Collect input notes from actions
let input_notes_vec: Vec<Note<CP>> = actions
    .iter()
    .map(|action| action.1.spend_note.clone())
    .collect();
let input_notes: [Note<CP>; NUM_NOTE] = input_notes_vec.try_into().unwrap();
// Collect output notes from actions
let output_notes_vec: Vec<Note<CP>> = actions
    .iter()
    .map(|action| action.1.output_note.clone())
    .collect();
let output_notes: [Note<CP>; NUM_NOTE] = output_notes_vec.try_into().unwrap();
// Construct VPs and generate VP proofs and blind VP proofs
let mut spend_slices = vec![];
let mut output_slices = vec![];
for _action_index in 0..NUM_TX_SLICE {
    // Construct dummy spend slice
    let mut spend_addr_vp = FieldAdditionValidityPredicate::<CP>::new(
        input_notes.clone(),
        output_notes.clone(),
        &mut rng,
    );
    let spend_addr_vp_check = VPCheck::build(&mut spend_addr_vp, &mut rng).unwrap();
    let mut spend_app_vp = FieldAdditionValidityPredicate::<CP>::new(
        input_notes.clone(),
        output_notes.clone(),
        &mut rng,
    );
    let spend_app_vp_check = VPCheck::build(&mut spend_app_vp, &mut rng).unwrap();
    let spend_slice = SpendSlice::new(spend_addr_vp_check, spend_app_vp_check);
    spend_slices.push(spend_slice);
    // Construct dummy output vps
    let mut output_addr_vp = FieldAdditionValidityPredicate::<CP>::new(
        input_notes.clone(),
        output_notes.clone(),
        &mut rng,
    );
    let output_addr_vp_check = VPCheck::build(&mut output_addr_vp, &mut rng).unwrap();
    let mut output_app_vp = FieldAdditionValidityPredicate::<CP>::new(
        input_notes.clone(),
        output_notes.clone(),
        &mut rng,
    );
    let output_app_vp_check = VPCheck::build(&mut output_app_vp, &mut rng).unwrap();
    let output_slice = OutputSlice::new(output_addr_vp_check, output_app_vp_check);
    output_slices.push(output_slice);
}
// Construct a tx
let tx = Transaction::<CP>::new(action_slices, spend_slices, output_slices);
```
This transaction `tx` can be verified, meaning that the VPs, action and blinding proofs are checked.
In addition, this verification checks the consistency of the public inputs from the above proofs and the ledger status (root existence, nullifier non-existence, etc.).
```rust
// Tx verification
tx.verify(ledger_status)?;
```

This code is reproducible with [this file](https://github.com/anoma/taiga/blob/main/src/doc_examples/transaction.rs) with the following command:
```
cargo test --release test_tx_example
```

### Example

Alice is a user of Taiga with validity predicates defined as follows:
* `SendVP` is a check on the amount of her spent: she does not want to send more than 3XAN (Anoma native token) at a time.
* `RecvVP` is a check on the amount she receives: she does not want to receive notes of less than 0.1XAN.

```rust
    ...
    // compose the VPs with the methods defined earlier
    // check ../../doc_examples/users.rs to see the defined methods
    let mut send_vp = SendVP::<CP>::new(send_input_notes, send_output_notes);
    let mut recv_vp = ReceiveVP::<CP>::new(receive_input_notes, receive_output_notes);

    // transform VPs into a different form
    let desc_vp_send = ValidityPredicateDescription::from_vp(&mut send_vp, &vp_setup).unwrap();
    let desc_vp_recv = ValidityPredicateDescription::from_vp(&mut receive_vp, &vp_setup).unwrap();

    let alice = User::<CP>::new(
        desc_vp_send, // SendVP
        desc_vp_recv, // RecvVP
        NullifierDerivingKey::<Fr>::rand(&mut rng), // nullifier key
    );

    // compute the address
    // it can be used to send notes to Alice
    let _alice_addr = alice.address().unwrap();
```

This example is reproducible with [this file](../../src/doc_examples/user.rs) or with the command

`cargo test doc_examples::user::test_app_creation`

### App Examples
##### Create an application
As `appVP` basically defines the application, creating an application is done by creating its `appVP`.

Let's use the [`TrivialValidityPredicate`](../validity-predicates.md) we defined earlier. It does nothing and returns `true`:
```rust
// trivial VP checks nothing and returns Ok()
let mut app_vp = TrivialValidityPredicate::<CP> {
	input_notes,
	output_notes,
};

// transform the VP into a circuit description
let desc_vp = ValidityPredicateDescription::from_vp(&mut app_vp, &vp_setup).unwrap();

let app = App::<CP>::new(desc_vp);

//app address can be used to create notes of that app
let app_address = app.address().unwrap();
```
See the example code [here](https://github.com/anoma/taiga/blob/main/taiga_zk_garage/src/doc_examples/app.rs)

#### Dummy application

It is also possible to create a dummy application without a VP (used to create dummy notes):

```rust
let app = App::<CP>::dummy(&mut rng)
```
