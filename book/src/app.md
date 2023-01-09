
Every [application](./app.md) in Taiga has a validity predicate that contains its rules (e.g. a token application checks the transaction balance).



# Application

Similarly to Ethereum applications that are build on smart contracts, Taiga applications have VPs that define the application rules. Every application is identified by its address and has its own note type. Sending and receiving the notes of the app type is controlled by the `appVP`.

#### Example
- a cryptocurrency application with a note type CUR (matches the token name) and `appVP` that makes sure that the balance is correct

### Application VP
Each application has its own [`appVP`](./validity-predicates.md) that defines the conditions on which the application can be used (i.e. the notes of the corresponding type can be sent or received). 

Like all other VPs, `appVP` is required to evaluate to `true` in a valid transaction and shielded with the help of ZK proofs.

#### Application Address
Each application is identified by an address that is derived from its verifier key `app_VK` (that is itself derived from the `appVP`):
`appAddress = Com(app_VK)`. Notes are linked to applications through the app address field of a note. 

TODO: link to a VK definition
