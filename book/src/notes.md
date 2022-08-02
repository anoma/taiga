# Notes

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