# Universal PLONK

A PLONK circuit corresponds to five polynomials `q_L(X), q_R(X), q_M(X), q_O(X), q_C(X)` that encode the arithmetic, three polynomials `S_1(X), S_2(X), S_3(X)` that encode the copy constraints and three secret polynomials `f_a(X), f_b(X), f_c(X)`. In this section, we detail how we adapt the initial PLONK construction in order to be able to plug any homomorphic PCS. The prover computation splits in five rounds:
1. **Commitment (part 1)** Randomize `f_a, f_b, f_c` in order to obtain `a(X), b(X), c(X)`. Commit to these three polynomials.
2. **Commitment (part 2)** Compute a polynomial `acc(X)` that encodes the copy constraints corresponding to the secrets `f_a,f_b,f_c`. Then, randomize it in order to get `z(X)` and commit to it.
3. **Commitment (part 3)** Compute a very large polynomial `t(X)` encoding the circuit. `t(X)` is not blinded because it is related to `q_L`, `q_R`, etc that are public information, and `a(X)`, `b(X)` and `c(X)` that are already randomized version of `f_a`, `f_b` and `f_c`. Commit to `t(X)`.
4. **Opening (part 1)** For a challenge `ζ`, evaluate `a(X),b(X),c(X),S_1(X),S_2(X),S_3(X),t(X),z(X)` and `z_w(X)=z(wX)` at `ζ`. 
5. **Opening (part 2)** two polynomials at `ζ` (related to all what is above).

Then, the verification corresponds to:
1. Recompute `t(ζ)` using all the evaluations of `a(X), b(X), c(X), q_L(X), q_R(X), ...` at `ζ`.
2. Compute the full commitment using all the points
3. Verify both opening with a linear combination.

Note that in PLONK, the verifier also manipulates commitments to the circuit polynomials `q_L(X)`, etc. These form a `VerifierKey` and is the part that we will need to blind in order to get private circuits. 