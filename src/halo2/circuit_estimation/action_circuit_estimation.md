# Action circuit cost in Halo 2

We provide three estimations of the Halo 2 Action circuit cost.
1. [A first estimation](./action_estim_1.md) simply counts the number of hashes in the action circuit (in our current Taiga design), and computes these hashes in Halo 2.
2. (TBD) [A second estimation](./action_estim_2.md) estimate the cost when we benefits of different commitment scheme when it is possible (hashing to curve may be faster than Poseidon).
3. (TBD) [A third estimation](./action_estim_3.md) computes the overall circuits including the range gate, the conversion into bits and other small circuits, including the variable setting in the circuit, etc.
