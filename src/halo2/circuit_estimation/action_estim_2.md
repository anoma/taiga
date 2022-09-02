# Action circuit estimation (version 2)

Action circuit is composed of:
* a merkle tree membership circuit,
* opening user addresses (both with sending and receiving VPs),
* opening token addresses,
* computing nullifiers,
* computing note commitments.

## ZK-Garage and Halo 2 primitives

We apply several changes in our current design for efficiency reasons:
* We modify the note commitment definition: instead of using Poseidon8, we use Sinsemilla.
* User and token addresses are committed into the base field, and then committed into the scalar field.
    * In the case of the pairing setting, a base field element is larger than a scalar field element.
    * In the case of Halo 2, base field and scalar field of Vesta are of the same size and so we can use Poseidon2 instead of Poseidon4 in the address computation.

For a first version, we keep the merkle tree with Poseidon hashes.

## Approximated cost

Using these modifications, we can estimate the cost of the action circuit with a bit of refinement. Each action requires 5 `BitsToVariables` + 39 `Poseidon2` + 1 `Poseidon4` + 2 `Sinsemilla` + 2 `RangeGate64`.

In this second estimation, we integrate Sinsemilla hashes and implement Poseidon4.
* Poseidon4 required the generation of parameters as for ZK-Garage; it was quite easy, but there are some tests vectors that I was not able to reproduce (probably easy though).
* For Sinsemilla, I use the Orchard Parameters but we could generate them or reproduce them later.

For `NUM_NOTES = 4`, we have 39*4 Poseidon2 + 1*4 Poseidon4 + 2*4 Sinsemilla. This circuit fits in 2¹³ constraints (without any optimizations) and we obtained the following timings:
```
key generation: 	10826ms
proof: 			    2760ms
verification: 		36ms
```
