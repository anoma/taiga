# Note

`Note` is an immutable object that represents a unit of value of a certain token. Each note has an [owner](users.md), a [token](token.md) type, and a value:

```rust
pub struct Note<CP: CircuitParameters> {
	pub owner: User<CP>,
	pub token: Token<CP>,
	pub value: u64,
...
}
```

#### Sending notes

As the notes are immutable, sending a note (transfering the ownership) means **destroying** the existing note (spent note) and **creating** a new note (output note) with a different owner.

`Note(owner: A, token: T, value: V) -> Note(owner: B, token: T, value: V)`

To send a note, the owner needs to prove the ownership which is done by revealing note's nullifier `nf`.  The nullifier is only known to the owner of the note and revealing it destroys the note. All revealed nullifiers are stored in a public nullifier tree `NFtree` to make sure none of the notes are spent twice.

##### Proving ownership in ZK
All of the notes are kept shielded and created notes are sent to users in an encrypted form. To keep the notes shielded, ZK proofs are used. Using ZK proof, one can prove the ownership without revealing the note itself (see [Action circuit](action.md)).

#### The commitment tree

Each created note exists in a public merkle tree `CMtree` of notes. To keep the notes schielded, the tree contains note commitments `cm` instead of the notes themselves. This tree is called a note commitment tree.

#### Note structure
The full description of the note structure is

```rust
pub struct Note<CP: CircuitParameters> {
	pub owner: User<CP>,
	pub token: Token<CP>,
	pub value: u64,
	pub data: CP::CurveScalarField,
	pub rho: Nullifier<CP>,
	pub psi: CP::CurveScalarField,
	pub rcm: CP::CurveScalarField,
}
```

, where:
- `data` is additional information that might be useful to describe notes of a certain type (e.g. NFTs)
- `rho`  and `psi` are the values used to compute the note's nullifier
- `rcm` is randomness used to compute the commitment `cm`


#### Creationg a note
TODO: add a hyperlink to the existing code 
We provide an example of creation of a note from the structure we have already defined for [Token]() and [User]():
```rust
// ...
// we use the code of the previous sections
// ...

// token and user
let desc_vp_token = ValidityPredicateDescription::from_vp(&mut vp, &vp_setup).unwrap();
let desc_vp_send = desc_vp_token.clone();
let desc_vp_recv = desc_vp_send.clone();

let tok = Token::<CP>::new(desc_vp_token);
let alice = User::<CP>::new(
	desc_vp_send,
	desc_vp_recv,
	NullifierDerivingKey::<Fr>::rand(&mut rng),
);
// note
let nf = Nullifier::<CP>::new(Fr::rand(&mut rng));
let note = Note::<CP>::new(alice, tok, 12, nf, Fr::rand(&mut rng), Fr::rand(&mut rng));

let _note_commitment = note.commitment();
```
This example can be run from [this file](https://github.com/anoma/taiga/blob/main/src/doc_examples/note.rs) with the command:
```
cargo test doc_examples::note::test_note_creation
```

#### Dummy notes
Dummy notes might be useful to keep the the amount of notes constant and hide the actual amount of notes in a tx.

```rust
let spend_note = Note::<CP>::dummy(&mut rng);
```

Next: [action](./action.md)