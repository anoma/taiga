# Conclusion

We presented the different structures needed to build a transaction in Taiga. This includes:
* Tokens, and their corresponding validity predicate proofs,
* Users, and their corresponding sending and receiving validity predicate proofs,
* Notes, with their fields including the user owner address and the token address,
* The action proof that binds the different VPs to the note fields,
* The blinding proof that enables full privacy of VP,
* The transaction description that enables spending and creating notes by verifying the different proofs.

For a technical overview of Taiga, see the [technical specification](spec.md).

In practice, the performance of our current implementation heavily depends on the size of the circuits, but also the number of proofs.

## Performance
The performance is significantly affected by the proof generation, i.e. the number of proofs and the size of the different circuits.

In a transaction, the action and the blinding circuit are fixed. The VP circuit size depends on the number of notes and the custom constraints set by the users and tokens.
As we have seen in the [transaction](/book/src/transaction.md), the number of notes in a transaction affects the number of proofs: for `NUM_NOTES` notes in a transaction, there is `9 * NUM_NOTES` proofs to be computed (of different circuit size).
We provide here the benchmarks of a transaction for different numbers of notes.

### Performance of the action and blidning proofs
The performance of the action and blinding proofs are independent from the number of notes. In our current implementation, action and blinding circuit has roughly $2^{15}$ gates.

|Action proof step|Time|Blinding proof step|Time|
|-|-|-|-|
|Compile|4s|Compile|17s|
|Prove|4s|Prove|19s|
|Verify|9ms|Verify|43ms|

### Performance of a VP proof
Customizable VPs will have different number of gates. We provide here the benchmark for $2^{17}$ gates:

|Operation |Time|
|-|-|
|Compile|17s|
|Prove|17s|
|Verify|14ms|

### Performance of a transaction

From the previous benchmarks, we can perform a full transaction with different numbers of notes:
* With `NUM_NOTE = 4`, a transaction includes 4 action proofs, 16 VP proofs and 16 blinding proofs:

|Operation |Time|
|-|-|
|vp compile + tx prove|1160 s|
|verify|844ms|

* With `NUM_NOTE = 3`, a transaction includes 3 actions proofs, 12 VP proofs and 12 blinding proofs:

|Operation |Time|
|-|-|
|vp compile + tx prove|591 s|
|verify|587ms|

* With `NUM_NOTE = 2`, a transaction includes 2 action proofs, 8 VP proofs and 8 blinding proofs:

|Operation |Time|
|-|-|
|vp compile + tx prove|436 s|
|verify| 555ms|


### Potential performance improvement
The overall cost of a transaction is too expensive but there are several way of improvements:
* The proof generation can be parallelized between the different actors of Taiga (sender, receiver, token, etc.)
* Circuits are not optimized and the size can be reduced by improving the basic gadgets, refining the local data, etc.
* The proof system can be modified so that we can use accumulation/aggregation, and/or use another polynomial commitment scheme leading to different efficiency tradeoffs.

# The next steps
Still, there are several circuits and implementation tasks to do in order to make Taiga working completely:
* The action and the blinding circuits require an implementation of a hash function that can be efficient over two fields. We plan to use the Blake2 function but the circuit is not available in the PLONK implementation of ZK-Garage [#56](https://github.com/anoma/taiga/issues/56). However, there is an implementation from Joshua that could be adapted.
* We use Poseidon for hashing into `MainCurve::BaseField`. It requires generating parameters that do not work for this size of modulus.
* The encryption part of Taiga is not implemented yet. A verifiable encryption circuit [#7](https://github.com/anoma/taiga/issues/7) needs to be chosen and implemented.
* We need to write more (useful) validity predicate examples [#5](https://github.com/anoma/taiga/issues/5).
* New structures (`vp_param` and `vp_memo`) need to be defined for validity predicates.
* The ledger integrity [#6](https://github.com/anoma/taiga/issues/6) needs to be implemented (e.g. the commitment tree implementation, the interface with the ledger, etc.).
* Our current blinding method is not fully blinding: σ polynomials of the PLONK constructions are still not blinded and it is not possible to apply the same method. Though, there are way of achieving full blinding by using an accumulator as they do in VeriZexe.
* Moving to a new polynomial commitment scheme like Halo 2 would let us achieve full recursive zero-knowledge proofs. Although it is not required for make Taiga work, it is an interesting optimization for reaching efficient ZK proofs.