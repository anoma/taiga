# Proof of blinding

The main difficulty with blinding the `VerifierKey` is that the prover can actually cheat and consider *any* circuit! Thus, we need a way to tie the private circuit and its randomized version. We do it using another circuit:

1. Alice has a circuit, and a commitment to this circuit that lets us identify her.
2. Alice computes the blinding version of the circuit.
2. Alice computes a proof of this circuit.
3. Alice computes a proof that the blinded `VerifierKey` has been computed using a circuit that commits to its identifier (called her address, see this section (TODO url)).
4. The verifier can verify the proof of the private circuit using the blinded `VeriferKey`, and verify the blinding using a blinding circuit.

In the next section, we provide an example with KZG.