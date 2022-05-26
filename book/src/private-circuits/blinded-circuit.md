# Blinded circuit

Private circuits are obtained by randomizing the `VerifierKey`. In both IPA and KZG, a commitment is a point of the curve defined over a prime field. In order to randomize the circuit commitment of the `VerifierKey`, we compute the commitment of `q(X) + r*Z_H(X)` (where `Z_H(X)` is the vanishing polynomial and `r` is a random finite field element) instead of `q(X)`. In this way, we obtain a different `VerifierKey`, but it corresponds to the same circuit because adding a multiple of `Z_H` does not change the circuit considered. 

If a curve is used for producing a proof of a circuit, the proof of the blinding will be defined with another curve. Moreover, a third curve can be used for specific circuits.

## Curve, inner curve and Outer curve

In practice, circuit can correspond to elliptic curve arithmetic. For instance, we could consider a signature check algorithm (using ECDSA).
In this context, we need *three* curves in order to produce private circuit proofs.

* **Inner curve.** We consider a circuit correspond to arithmetic on a curve `InnerCurve` defined modulo `q`.
* **Curve.** For the proof corresponding to the circuit modulo `q`, we consider a curve `Curve` defined modulo `p` with a subgroup of order `q`.
* **Outer curve.** For blinding the circuit, we need to compute arithmetic modulo `p`, meaning that we need a curve with a subgroup of order `p`.

| Elliptic curve | Base field | Scalar field |
|-|-|-|
|InnerCurve|`Fr`|-|
|Curve|`Fq`|`Fr`|
|OuterCurve|-|`Fq`|


## Examples

### Signature check with the KZG PCS

We consider the ECDSA signaturee and the KZG polynomial commitment scheme. It means that the proofs are build over a pairing-friendly curve. We consider `Curve = bls12_377` so that we can set `InnerCurve = ed_on_bls12_377` and `OuterCurve = bw6_761`.

* The signature public key is defined over `bls12_377 base field`.
* The signature check circuit is defined over `ed_on_bls12_377 base field`, i.e. `bls12_377 scalar field`.
* The proof is defined over `bls12_377 base field`, as well as the `VerifierKey`.
* The blinding circuit is defined over `bls12_377 base field`, i.e. `bw6_761 scalar field`.
* The blinding proof is defined over `bw6_761 base field`.

### Signature check with the IPA PCS

The latter construction can be done with the IPA polynomial commitment scheme. In this context, the proofs can be built over non-pairing-friendly curves. For the same level of security, we can use a curve is defined over a smaller field compared to the pairing case above.
We can consider `Curve = Vesta`, and set `InnerCurve = OuterCurve = Pallas`. Indeed, the Pasta cycle of curves satisfies `PallasBaseField = VestaScalarField` (required for the inner curve) and `PallasScalarField = VestaBaseField` (required for the outer curve).

### Hash function check with the KZG PCS

We consider the circuit corresponding to a hash function. In this context, we don't need an inner curve and we can set `Curve = bls12-377` and `OuterCurve = bw6_761`.