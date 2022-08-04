# Conclusion

We need to talk about what is still not possible: blake2 circuit, full blinding because of σ polynomials, accumulation for efficiency (and/or change of proof system?).
* What we are able to do
* What we don't have yet: blake2 circuit, hash to BaseField, etc.

## Performance
The performance is significantly affected by the proof generation, i.e. the number of proofs and the circuit size of the proof.

In a transaction, the `Action circuit` and `Blind VP circuit` are fixed. The VP circuit size is decided by the number of notes and the custom constraint. The number of proofs are decided by the number of notes. Therefore, we tested the tx performance with different numbers of notes.

### Performance of Action Proof and Blind VP Proof
The performance of `Action Proof` and `Blind VP Proof` are independent from the number of notes.
|Type(Circuit Size)|Operation |Time|
|-|-|-|
|Action(2^15)|Compile|secs: 4, nanos: 975182000|
|Blind VP(2^15)|Compile|secs: 17, nanos: 505948000|
|Action(2^15)|Prove|secs: 4, nanos: 678785000|
|Blind VP(2^15)|Prove|secs: 19, nanos: 338197000|
|Action(2^15)|Verify|secs: 0, nanos: 9618000|
|Blind VP(2^15)|Verify|secs: 0, nanos: 43840000|

### Tx Performance With NUM_NOTE = 4
#### One VP Performance
|Type(Circuit Size)|Operation |Time|
|-|-|-|
|VP(2^17)|Compile|secs: 17, nanos: 505948000|
|VP(2^17)|Prove|secs: 17, nanos: 735556000|
|VP(2^17)|Verify|secs: 0, nanos: 14212000|

#### Tx Performance
The transaction(with NUM_NOTE = 4) includes 4 action proofs, 16 vp proofs and 16 vp blind proofs.
|Operation |Time|
|-|-|
|vp compile + tx prove|secs: 1160, nanos: 198469000|
|verify|secs: 0, nanos: 844403000|

### Tx Performance With NUM_NOTE = 3
#### One VP Performance
|Type(Circuit Size)|Operation |Time|
|-|-|-|
|VP(2^16)|Compile|secs: 10, nanos: 87050000|
|VP(2^16)|Prove|secs: 10, nanos: 71476000|

#### Tx Performance
The transaction(with NUM_NOTE = 3) includes 3 action proofs, 12 vp proofs and 12 vp blind proofs.
|Operation |Time|
|-|-|
|vp compile + tx prove|secs: 591, nanos: 227595000|
|verify|secs: 0, nanos: 587065000|

### Tx Performance With NUM_NOTE = 2
#### One VP Performance
|Type(Circuit Size)|Operation |Time|
|-|-|-|
|VP(2^16)|Compile|secs: 9, nanos: 987286000|
|VP(2^16)|Prove|secs: 9, nanos: 946505000|

#### Tx Performance
The transaction(with NUM_NOTE = 2) includes 2 action proofs, 8 vp proofs and 8 vp blind proofs.
|Operation |Time|
|-|-|
|vp compile + tx prove|secs: 436, nanos: 500172000|
|verify|secs: 0, nanos: 555699000|


### Potential Performance Improvement
* Proofs generation parallelization
* Circuit improvement, e.g. basic gadgets improvement, local data refinement, etc
* Proof system improvement, e.g. change to Halo2, use accumulation or aggregation.
