# User

Each Taiga user has an **address** that identifies them, **validity predicates** that authorize their actions, and **keys** that are used to derive parameters.

### Validity predicates
Each user has VPs that authorize spending (`sendVP`) and receiving (`recvVP`) notes and `intentVP` that is used to specify the intents of the user.

TODO: add intent link

As VPs are shielded in Taiga, instead of showing that the VPs of the user evaluate to `true` publicly, ZK proofs are created. An observer can verify these proofs using the verifier key.

### Keys
Each user has a set of keys that allows to authorize various actions or generate parameters. One of such keys is a nullifier key `nk` used to compute [note nullifiers](./notes.md) that are necessary to spend notes.

### Address

Each user has an address that allows others to send assets to the user. Address is derived from user's `SendVP`, `RecvVP`, and `nk`.
