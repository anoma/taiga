# Taiga action circuit with Halo 2

## Action circuit composition

First, we estimate the Action circuit in our current Taiga. The design is going to change when we migrate to Halo 2, but we can start with this approximation.

Action circuit splits into input and output note constraints.

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

### Overall action circuit
An action circuit spend one note and create one note. Its total cost is
```
5 `BitsToVariables` + 4 `Poseidon2` + 4 `Poseidon4` + 2 `Poseidon8` + 2 `RangeGate64`
```
The number of action circuits in a transaction grows linearly with the number of notes (as an action circuit spends one note and create another note). We obtain the following count:

|`NUM_NOTES`|`BitToVariables`|`Poseidon2`|`Poseidon4`|`Poseidon8`|`RangeGat64`|
|-|-|-|-|-|-|
|2|10|8|8|4|4|
|3|15|12|12|6|6|
|4|20|16|16|8|8|
|$n$|5$n$|4$n$|4$n$|2$n$|2$n$|


## Dummy Halo 2 circuits

We create a dummy circuit of a size comparable to our current Taiga.
As Poseidon is used a lot in our current design, we target this first circuit. It is actually way smaller in Halo 2 and a circuit of size 2¹⁶ corresponds to 1000 hashes! The proof computation is very fast: 
```
key generation: 	66418ms
proof: 			11199ms
verification: 		204ms
```

It would make more sense to compare the actual circuit. The size is not a good way of comparison. See the todo.


## To by done

TODO:
* Benchmark the Poseidon2 against Poseidon4 and Poseidon8 in PLONK and Halo2 and compare them
* Benchmark BitsToVariables in Halo2 and compare with PLONK
* Compute a dummy circuit corresponding to Taiga action and compare the timings.

TODO++:
* Understand the blinding with an accumulator
* Estimate the size in terms of Halo2 circuits
* Write down a conclusion on the circuits.
