# Blinding

In the previous section, we explained how we bind the different proofs to the spent and created notes. In this section, we focus on the privacy of the verifier keys of these proofs.

Each verifier key is randomized so that two transactions with the same VPs cannot be binded. When a user or a token provides a proof, it randomizes the verifier key so that the proof can be verified with a new verifier key, and computes a new commitment to the non-blinded verifier key. Then, a blinding proof is required in order to bind the two verifier keys.
