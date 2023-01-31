# Application

Every application in Taiga has a validity predicate called `appVP` that contains the application logic. The application state is stored in the notes, spending or creating application notes alters the application state and requires the approval from `appVP`.

#### Example

- a cryptocurrency application CUR (matches the token name) and `appVP` that makes sure that the transaction is balanced

#### Is it like Ethereum?

In some sense, Taiga applications are similar to Ethereum applications, but there are two key distinctions that come to mind:
* Ethereum uses smart contracts (imperative) when Taiga uses validity predicates (declarative) to express the application logic
* Taiga applications are shielded by default, but can be defined over the transparent pool as well


### Application VP
Each application has an [`appVP`](./validity-predicates.md) that defines the conditions on which the application can be used (i.e. the application notes can be sent or received). Every time a note that belongs to the application is spent or created, `appVP` is called to authorize the transaction.`AppVP` might also require validity of other VPs, enforcing a VP hierarchy.

#### Application Address
Every application is identified by an address that is derived from its `AppVP` circuit verifying key `app_vk`:
`appAddress = Com(app_vk)`. 

#### Application notes

Notes that belong to different applications have distinct types, but notes within the same application can have distinct types as well (to express the difference in usage). The note type is encoded in the notes value base (see more here). Notes of different types are independent of each other (unless explicitly designed).

### Applications interaction
TBD

### Application users
TBD

Some applications might have users. In that case the application is responsible for making the users' interests satisfied, e.g. by allowing `userVP` and enforce the check in the `appVP`