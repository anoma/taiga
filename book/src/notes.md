# Note

A **note** is an immutable object that represents a unit of value. Each note belongs to a certain application (which defines the note's type), and can store some data:

```
#[derive(Debug, Clone, Default)]
pub struct Note {
pub value_base: NoteType,
/// app_data_dynamic is the data defined in application vp and will NOT be used to derive value base
/// sub-vps and any other data can be encoded to the app_data_dynamic
pub app_data_dynamic: pallas::Base,
/// value denotes the amount of the note.
pub value: u64,
/// the wrapped nullifier key.
pub nk_com: NullifierKeyCom,
/// old nullifier. Nonce which is a deterministically computed, unique nonce
pub rho: Nullifier,
/// computed from spent_note_nf and rcm by using a PRF
pub psi: pallas::Base,
pub rcm: pallas::Scalar,
/// If the is_merkle_checked flag is true, the merkle path authorization(membership) of the spent note will be checked in ActionProof.
pub is_merkle_checked: bool,
/// note data bytes
pub note_data: Vec<u8>,
}

/// The parameters in the NoteType are used to derive note value base.
#[derive(Debug, Clone, Default)]
pub struct NoteType {
/// app_vk is the verifying key of VP
app_vk: ValidityPredicateVerifyingKey,
/// app_data is the encoded data that is defined in application vp
app_data: pallas::Base,
}
```

#### Sending notes

As the notes are immutable, sending a note (transfering the ownership) means **destroying** the existing note (spent note) and **creating** a new note (output note) with a different owner.

`Note(owner: A, application: T, value: V) -> Note(owner: B, application: T, value: V)`

To send a note, the owner needs to prove the ownership which is done by revealing note's nullifier `nf`.  The nullifier is only known to the owner of the note and revealing it destroys the note. All revealed nullifiers are stored in a public nullifier tree `NFtree` to make sure none of the notes are spent twice.

##### Proving ownership in ZK
All of the notes are kept shielded and created notes are sent to users in an encrypted form. To keep the notes shielded, ZK proofs are used. Using ZK proof, one can prove the ownership without revealing the note itself (see [Action circuit](action.md)).

#### The commitment tree

Each created note exists in a public merkle tree `CMtree` of notes. To keep the notes shielded, the tree contains note commitments `cm` instead of the notes themselves. This tree is called a note commitment tree.

#### Note structure
The full description of the note structure is

```rust
pub struct Note<CP: CircuitParameters> {
	pub owner: User<CP>,
	pub app: App<CP>,
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

#### Dummy notes
Dummy notes might be useful to keep the amount of notes constant and hide the actual amount of notes in a tx.
