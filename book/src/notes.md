# Notes

* Note contains: owner address, token address, value, nullifier (open or closed), randomness (for the note commitment below)
* Note are committed for privacy. It commits to all the data inside a note.
* When a note is spent:
    * a proof of the sendVP is verified against a `SendVK`.
    * a proof of the tokenVP is verified against a `TokenVK`.
    * the nullifier is computed using `nk`.
    * the note commitment is open with all the data inside.
    * we bind the owner address to `SendVK` and `nk`.
    * we bind the token address to `TokenVK`.
* When a note is created:
    * a proof of the RecvVP is verified against `RecvVK`.
    * a proof of the tokenVP is verified against a `TokenVK`.
    * the address of the new note owner is computed using `RecvVK`
    * the address of the new note token is computed using `TokenVK`.
    * we create the note commitment using the data above (and other things like `rcm`, etc).


-----



Notes contains more informations than users and tokens:
* An owner which is a user,
* A token type,
* A value, corresponding to the amount of tokens,
* A nullifier,
* Some data (not useful for my explanation),
* A random value useful for getting full privacy latter.

When a note is spent, there are lots of commitment to open in order to bind the users (the sender and the receiver) and the token:
* The sendin

a bit more complex than users and tokens because it binds two users (the sender and the receiver) and two tokens (the spent note token and the created note token).

        user: User<CP>,
        token: Token<CP>,
        value: u64,
        rho: Nullifier<CP>,
        data: CP::CurveScalarField,
        rcm: CP::CurveScalarField,

* Defininition
* Address definition and binding with sender and receiver
* Nullifier definition
* `cargo test`