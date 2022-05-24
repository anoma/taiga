# Private circuits

From the transparent Anoma, we obtain PBC by adding privacy on the circuit we consider. In this way, one cannot break privacy by looking at the circuits involved in a given proof. As circuits can be personalized, a circuit clearly leaks information on the user.

In this section, we give a little bit more details on PLONK, and then explain how we can blind the PLONK circuit. Finally, we detail how we can ensure that the real and the blinded circuits are connected, using another PLONK proof. We end this section with an example of blinding circuit.