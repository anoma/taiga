# Action circuit estimation (version 2)

Action circuit is composed of:
* a merkle tree membership circuit,
* opening user addresses (both with sending and receiving VPs),
* opening token addresses,
* computing nullifiers,
* computing note commitments.

## ZK-Garage and Halo 2 primitives

As a first step, we want to change only the note commitment computation. Instead of using Poseidon8, we will use Sinsemilla.

User and token address use a base field commitment, and split them into two scalar field elements because with BLS12-381, log(p) = 381 and log(r) = 256. In the case of Vesta, we can actually use only one field element, and use Poseidon2 instead of Poseidon4.

Finally, we are going to keep the Merkle tree as it is, even though we could switch to Sinsemilla as they do in Zcash. As a first version, we want to see if Poseidon can be okay.

## Approximated cost

Using this modification, we can estimate the cost of the action circuit with a bit of refinement. Each action requires 5 `BitsToVariables` + 39 `Poseidon2` + 1 `Poseidon4` + 2 `Sinsemilla` + 2 `RangeGate64`.

In order to get something a bit more precise, we implement Poseidon4 in the same way as we did in ZK-Garage, and we implement `BitsToVariable` and `RangeGate64`.

