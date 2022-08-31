# Blinding circuit with Halo 2

Estimating the blinding with Halo 2 is a bit more complex than the action circuit because it involves an accumuation, and it is not clear how it works for me.
Though, there are already some performance comparisons that can be done.

The blinding circuit is done over the outer curve.
* In the case of the pairing case, it is the BW6 curve and it is quite slow: it is defined over a ~760-bit prime and so circuits get very expensive.
* In Halo 2, because of the symmetry of Pallas and Vesta, we can compute the blinding proof over Pallas, which has the same properties as Vesta. Hence, the cost of the blinding circuit is way smaller than in the pairing case.

Though, the circuit is slightly different depending on the case, but we can expect something a lot faster because the field size is 256-bit in Halo 2, compared to 760-bit for the pairing case.

