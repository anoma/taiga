# Notes

A **note** is an immutable object that represents a unit of value. Each note belongs to a certain application (which defines the note's type), and can store some data.

#### Sending notes

As the notes are immutable, sending a note (transfering the ownership) means **destroying** the existing note (spent note) and **creating** a new note (output note) with a different owner.

`Note(owner: A, application: T, value: V) -> Note(owner: B, application: T, value: V)`

To send a note, the owner needs to prove the ownership which is done by revealing note's nullifier `nf`.  The nullifier is only known to the owner of the note and revealing it destroys the note. All revealed nullifiers are stored in a public nullifier tree `NFtree` to make sure none of the notes are spent twice.

##### Proving ownership in ZK
All of the notes are kept shielded and created notes are sent to users in an encrypted form. To keep the notes shielded, ZK proofs are used. Using ZK proof, one can prove the ownership without revealing the note itself (see [Action circuit](action.md)).

#### The commitment tree

Each created note exists in a public merkle tree `CMtree` of notes. To keep the notes shielded, the tree contains note commitments `cm` instead of the notes themselves. This tree is called a note commitment tree.

### Note structure fields

To understand the notes better, let's look at some fields in the note strucutre:

```rust
pub struct Note {
pub value_base: NoteType,
pub app_data_dynamic: pallas::Base,
pub value: u64,
pub nk_com: NullifierKeyCom,
pub is_merkle_checked: bool,
...
}
```
#### The application data
Note's `value_base` encodes the type of the note. The value base is derived from the application-specific data such as application VP, and some note-type-related details (e.g. for NFTs it would be the NFT description). As value base is the same for all notes of the same type, it should only include fairly long-term data, and the ephemeral data goes into `app_data_dynamic`. That field can contain input parameters for VP circuits, sub-VPs, and other data provided by the app.

#### Note values & dummy notes
For traditional applications like cryptocurrencies value field carries the traditional meaning e.g. USDC note of value 5 is equivalent to 5 dollars, but for more abstract applications the value field might change its meaning or loose it whatsoever. 
However, no matter that meaning the application gives to the value, value field is still used to check the transaction balance (learn more in the exec model desc)

Dummy notes are a sort of placeholders that don't a
ctually contain meaningful for the ledger data but look like real notes.
In some systems such as Zcash, dummy notes are identified by their values - zero value note is considered dummy. However, this isn't true for Taiga. As Taiga generalizes the idea of a note, zero-value notes can still be important, so in Taiga we mark dummy notes by not checking the merkle path for them. `is_merkle_checked` flag marks if the note is dummy or not.

#### Who spends the notes?

Each note contains a field `nk_com` encoding the nullifier key (nk) of the note's owner. Notes don't have explicit owners, but are rather linked to the owner via the nullifier key. Whoever knows the nullifier key, can compute the note's nullifier and spend the note. The note doesn't contain the nullifier key itself, but only a commitment to it, which hides the key value (so it isn't enough to look at the note's content to be able to spend it).





