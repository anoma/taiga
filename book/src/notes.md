# Notes

A **note** is an immutable object that represents a part of the application state. Each note belongs to a certain application (that defines the note's type), and can store some data.

As notes are immutable, notes cannot be modified, only spent or created. "Modifying" a note would be done by spending the current note and creating the same, but modified, note.



##### Note privacy
The notes are distributed in an encrypted form, and only the owner knows the decryption key. 
To prove properties of the notes (e.g. ownership) without revealing the notes, we use ZK proofs.

#### The note commitment tree & the nullifier set

Each created note is added to a public Merkle tree. To keep the notes private, instead of the notes themselves, 
the tree contains note commitments `cm` that are binded to the actual notes. 
This tree is called a note commitment tree `CMTree`. 

Notes are never deleted from the note commitment tree, 
and to signal that the note has been spent and isn't valid anymore, its nullifier `nf` is added to the public nullifier set.

||`cm` isn't published|`cm` is published|
|-|-|-|
|`nf` isn't published|note doesn't exist|note created|
|`nf` is published|impossible|note spent|

### Note structure fields

Let's look at some fields in the note structure:

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
Notes contain quite a lot of data provided by the application the notes belong to. 
Part of that data is more long-term (e.g. the application VP) and used to derive the note's `value_base`, while
the other part is more contextual (e.g. the input parameters for the application VP) and is stored in `app_data_dynamic`. 
In general, all data that is not used to derive the value base is stored in the `app_data_dynamic`.

#### Note values
For more traditional applications like cryptocurrencies the `value` field carries the natural meaning 
e.g. a USDC note of value 5 is equivalent to 5 dollars, but for more abstract applications the value field might change its meaning or even loose it. 
However, no matter what meaning the application gives to the value, Taiga isn't aware of that and uses the `value` field of notes to check the transaction balance.

#### Dummy notes
Some notes in Taiga can be dummy, meaning that unlike "normal" notes, the merkle path isn't checked for them (indicated by the `is_merkle_checked` flag), 
but they can have arbitrary value and are stored in the commitment tree, just like "normal".

Being a dummy note and having zero value are two independent concepts in Taiga, unlike some other systems. 
Zero value notes aren't necessarily dummy, dummy notes can have non-zero value. 

#### Who owns the notes?

Each note contains a field `nk_com` encoding the nullifier key `nk` of the note's owner. 
Whoever knows the nullifier key, can compute the note's nullifier and spend the note. 
The field `nk_com` doesn't actually contain the nullifier key itself, but a commitment to it, 
which hides the key value (so it isn't enough to look at the decrypted note to be able to spend it).



