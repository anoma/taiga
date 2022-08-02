# Tokens

A token has a structure similar to a user. During a transaction, the token provides a proof for its rules together with the corresponding verifying key. As for users, this verifying key is binded to the token identity using the address: a commitment to the verifying key.

In conclusion, during a transaction, the token provides a proof for the token VP with the corresponding verifying key, and a proof that this later verifying key opens the token address provided as a public input.