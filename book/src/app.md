# Application

Similarly to Ethereum applications that are build with smart contracts, Taiga applications have VPs that define the application rules. 

#### Example
- a cryptocurrency application with a note type CUR (matches the token name) and `appVP` that makes sure that the balance is correct


#### Application state
Every application has a state that is stored in the application notes (the notes that belong to the application). Spending or creating application notes would alter the application state and would require a validation from the application.





### Application VP
Each application has its own [`appVP`](./validity-predicates.md) that defines the conditions on which the application can be used (i.e. the notes of the corresponding type can be sent or received). Every time a note that belongs to the application is spent or created, `appVP` is called to authorize the transaction.`AppVP` also might require validity of other VPs in order to count transaction as valid.

#### Application Data
Every application is identified by an address that is derived from its `AppVP` circuit verifying key `app_VK`:
`appAddress = Com(app_VK)`. 

Application notes have the application type (e.g. the application A has notes of type A) encoded in the note's value base, one application can have notes of multiple types (e.g. AA, AB, AC for application A). The notes of different types are independent (unless explicitly desired).

### Applications interaction
TBD