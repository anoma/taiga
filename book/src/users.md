# User

TODO: extract, merge, deprecate

Users:
- keys
  nullifier key `nk` is used to compute [note nullifiers](./notes.md) that are necessary to spend notes.
- VPs (userVP, send/recv VP, intent userVP, etc)
- Address

### Address

Each user has an address that allows others to send assets to the user. Address is derived from user's `SendVP`, `RecvVP`, and `nk`.
