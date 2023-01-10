# Application

Similarly to Ethereum applications that are build with smart contracts, Taiga applications have VPs that define the application rules. Every application is identified by its address and has its own note type. 

#### Example
- a cryptocurrency application with a note type CUR (matches the token name) and `appVP` that makes sure that the balance is correct

### Application VP
Each application has its own [`appVP`](./validity-predicates.md) that defines the conditions on which the application can be used (i.e. the notes of the corresponding type can be sent or received). Every time a note that belongs to the application is spent or created, `appVP` is called to authorize the transaction.`AppVP` also might require validity of other VPs in order to count transaction as valid.

#### Application Address
Each application is identified by an address that is derived from its VP circuit verifier key `app_VK`:
`appAddress = Com(app_VK)`. Notes are linked to applications through the app address field of a note.
