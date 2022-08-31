# Action circuit estimation (version 1)

Action circuit cost is dominated by Poseidon hashes.
Here, we estimate the number of Poseidon2 hashes in our current Taiga design with a lot of estimations that are not really accurate. 
Then, we create a dummy circuit in Halo 2 that computes this number of hashes and we estimate the proof computation and the verification time.

## Action circuit composition

First, we estimate the Action circuit in our current Taiga. The design is going to change when we migrate to Halo 2, but we can start with this approximation.

Action circuit splits into input and output note constraints, and a merkle tree circuit.

### Input note constraints
Input note constraints are split into user and token address integrity, opening of the note commitment, and the computation of the nullifier.

* User address integrity: 2 `BitsToVariables` and 2 `Poseidon4`,
* Token address integrity: 1 `BitsToVariables` and 1 `Poseidon2`,
* Note commitment opening: 1 `RangeGate64`, 1`Poseidon2` and 1 `Poseidon8`,
* Nullifier computation: 1 `Poseidon4`.

In total, 3 `BitsToVariables` + 3 `Poseidon4` + 2 `Poseidon2` + 1 `Poseidon8` + 1 `RangeGate64`.

### Output note constraints
Output note constraints are similar to input note constraints, but a bit lighter:

* User address integrity: 1 `BitsToVariables` and 1 `Poseidon4`,
* Token address integrity: 1 `BitsToVariables` and 1 `Poseidon2`,
* Note commitment opening: 1 `RangeGate64`, 1`Poseidon2` and 1 `Poseidon8`,

In total, 2 `BitsToVariables` + 1 `Poseidon4` + 2 `Poseidon2` + 1 `Poseidon8` + 1 `RangeGate64`.

### Merkle tree circuit

As in Orchard, we use a depth 32 Merkle tree for the input note, meaning that there are `32 Poseidon2` circuits more.

### Overall action circuit
An action circuit spend one note and create one note. Its total cost is
```
5 `BitsToVariables` + 36 `Poseidon2` + 4 `Poseidon4` + 2 `Poseidon8` + 2 `RangeGate64`
```
The number of action circuits in a transaction grows linearly with the number of notes (as an action circuit spends one note and create another note). We obtain the following count:

|`NUM_NOTES`|`BitToVariables`|`Poseidon2`|`Poseidon4`|`Poseidon8`|`RangeGat64`|
|-|-|-|-|-|-|
|1|5|36|4|2|2|
|2|10|72|8|4|4|
|3|15|108|12|6|6|
|4|20|144|16|8|8|
|$n$|5$n$|36$n$|4$n$|2$n$|2$n$|

An approximation can be done: `Poseidon4 = 2 Poseidon2` and `Poseidon8 = 2 Poseidon4 = 4 Poseidon2`, even if it is a bit more complex.
Thus, we get that for `n` notes, we computes roughly `36n + 8n + 8n = 52n Poseidon2` and other gates that we neglect for now.


## Dummy Halo 2 circuits

Poseidon hashes are the most expensive part of the circuit. We provide the estimations for 4 (in and out) notes per transactions.

We build a dummy circuit of 220 Poseidon2 hashes (`52 * 4 = 208`). We obtain the following benchmark:
```
key generation: 	15.26s
proof: 			    2.58s
verification: 		0.061s
```


