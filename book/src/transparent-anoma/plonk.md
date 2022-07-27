# PLONK in a nutshell

PLONK is a general-purpose zero-knowledge proof system based on a polynomial commitment scheme (PCS). In this section, we recall briefly what is a PCS and then describe how PLONK works, from a high level point of view.

## Polynomial Commitment Scheme

A polynomial commitment scheme is a way of proving the knowledge of a polynomial `P(X)`. It splits in three steps:
### Commitment
In this first step, the prover commits to a value related to `P`.

### Opening
Given a challenge `z` from the verifier, the prover computes a proof that is related to the latter commitment. He also computes the evaluation `P(z)`.

### Verification
From the opening proof, the verifier is able to check that the prover knows the polynomial commited in the first step and opened in the second step.

In PBC, we focus on two PCS:

* IPA, a PCS based on the discrete logarithm problem over an elliptic curve.
* KZG, a PCS based on the discrete logarithm problem over an elliptic curve and a finite field (also called the pairing assumptions).

KZG is succinct, meaning that the proof size and the verification time do not depend on the degree of `P`. IPA can be more efficient in practice because the security relies on a stronger problem. For example, in order to reach the 128-bit security level, one needs to use an elliptic curve defined over a 256-bit prime field for IPA and one can use the BLS12 curve defined over a (at least) 377-bit prime field for KZG.

PLONK uses a polynomimal commitment scheme where the commitment part is homomorphic, meaning that the commitment of `P+Q` is the sum of the commitments of `P` and `Q`. TODO: Do we really need that?

## PLONK

PLONK is a way of translating the knowledge of the solution of an arithmetic circuit into a proof. In PLONK, the gates of the circuits are additions and multiplications, but we can compute more complicated gates. In fact, gates are of the form `q_L a + q_R b + q_M ab + q_O c + q_C = 0`, where `a,b,c` is secret and the `q_i` are the public values defining the circuit. Given a circuit of `n` gates, PLONK describes a way to prove the knowledge of `a,b,c` satisfying the circuit by computing some commitment to `a,b,c`, and then opening two polynomials that translate all the circuit constraints. Thus, one can use any homomorphic PCS in order to commit and open the polynomials. Verifying the proof correspond to verify the two openings. Depending on the PCS choice, some optimizations are possible. For example, we can compute only one PCS verification in KZG, because of the bilinearity of the pairing.


