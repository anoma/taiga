# Transaction

## Overview
The structure `Transaction` defines all the information needed to be executed on the blockchain.
Once a transaction is executed successfully (i.e. verified), the ledger status will be transfered.
A transaction includes the proofs corresponding to the spending of input notes and the creation of output notes.

In our current implementation version, there are four input notes and four output notes in each transaction.
An action transfer contains one input note and one output note.
Each input note has one `send_VP` and one `token_VP`. Each output note has one `recv_VP` and one `token_VP`. Every validity predicate is blinded as described [here](blinding.md), leading to a blinding proof.
Therefore, a transaction includes:
* Four action proofs for the binding described [here](action.md),
* Four `send_VP` proofs corresponding to the four input notes owner addresses,
* Four `token_VP` proofs corresponding to the four input note token types,
* Four `recv_VP` proofs corresponding to the four output note owner addresses,
* Four `token_VP` proofs correspdonding to the four output note token types.
* Sixteen blinding proofs for the 16 previous proofs.

![](img/taiga_tx.png)

## Action Transfer Description
Each `Action Transfer` spends an input note and creates an output note(could be dummy notes). The `Action Proof` constrains the integrity of the notes, existence of input note on the `CommitTree`, the verifiable encryption of output note, and the vp commitments.

The detail can be found [here](action.md).

## Validity Predicate Description
There are two types of `Validity Predicate` so far, i.e., user vp(sender vp and recipient vp) and token vp. The `Validity Predicate` takes in local data(the notes in the tx) and custom data(vp defined data). And the `Validity Predicate Proof` describes basic constraints(the notes integrity) and custom constraints(vp defined).

The detail can be found [here](validity-predicates.md).

## Validity Predicate Blinding Description
To preserve the privacy of vp, we blind the vp description and generate a blind proof for each vp.

The detail can be found [here](blinding.md).

## How to construct a transaction
It's very flexible to construct a Taiga Transaction. A Transaction can be created from different users(roles) and splitted into several phases. In general, we can construct a transaction as the following procedures.
1. Construct the `Actions`.
2. Collect all the notes(input and output) from `Actions` as local data for VPs.
3. Construct `user VPs` and `token VPs`.
4. Generate `blind VP proofs`.
5. Construct a full transaction.

A transaction construction example:
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
    let mut spend_token_vp = FieldAdditionValidityPredicate::<CP>::new(
        input_notes.clone(),
        output_notes.clone(),
        &mut rng,
    );
    let spend_token_vp_check = VPCheck::build(&mut spend_token_vp, &mut rng).unwrap();
    let spend_slice = SpendSlice::new(spend_addr_vp_check, spend_token_vp_check);
    spend_slices.push(spend_slice);
    // Construct dummy output vps
    let mut output_addr_vp = FieldAdditionValidityPredicate::<CP>::new(
        input_notes.clone(),
        output_notes.clone(),
        &mut rng,
    );
    let output_addr_vp_check = VPCheck::build(&mut output_addr_vp, &mut rng).unwrap();
    let mut output_token_vp = FieldAdditionValidityPredicate::<CP>::new(
        input_notes.clone(),
        output_notes.clone(),
        &mut rng,
    );
    let output_token_vp_check = VPCheck::build(&mut output_token_vp, &mut rng).unwrap();
    let output_slice = OutputSlice::new(output_addr_vp_check, output_token_vp_check);
    output_slices.push(output_slice);
}
// Construct a tx
let tx = Transaction::<CP>::new(action_slices, spend_slices, output_slices);
```

## How to verify a transaction
In transaction verification, it verifies the action proofs, vp proofs and blind vp proofs. In addition, it checks the consistency of public inputs from above proofs and the ledger status(root existence, nf non-existence, etc).
```rust
// Tx verification
tx.verify(ledger_status)?;
```