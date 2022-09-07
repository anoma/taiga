
## Terminology

A *block* in the underlying chain contains many shielded transactions. Taiga maintains a state and processes transactions. A *transaction* consists of a set of input and output notes and a set of actions. 
- A *note* encodes a value $v$ of a specific application can be spent by a certain owner of the application. A note contains pointers (i.e. addresses) to a application and to a user.
- An *action* is a circuit that verifies a note can be spent, that is, the conditions defined in the user and application validity predicates are met and the note was not previously spent.

The *address* of a application or a user consists of a commitment of the application validity predicate or the user validity predicate, respectively. That is, a application or user address is uniquely identified by the rules of the underlying validity predicate.

## Validity Predicate Model

*Validity predicates* can be seen as a set of rules (i.e. a circuit) that assess the truth of a statement. They are used to determine whether a state transition is valid or not. During the execution phase of a transaction, both the validity predicates associated with the sender/receiver and the application involved will be called. Each triggered validity predicate will independently evaluate this state change, which will either be accepted or rejected based on the evaluation. As validity predicates are very flexible, they can be tailored to handle a variety of use cases.

As validity predicates are stateless, they can be parallelized.

## Related work

### ZEXE

Decentralised exchanges with privacy guarantees without requiring users to give up custody of their assets were first studied in the [Zexe paper](https://eprint.iacr.org/2018/962.pdf).

Zexe uses Groth16 as its underlying proving system, whereas Taiga uses Plonk. The choice of a proving system determines the design of private computation in the protocol.

Zexe describes how simple private contracts can be implemented, but leaves as an open problem how to implement full generality.

### Penumbra

### Bilateral swaps (Aztec)

### ZCash Orchard

Privacy but not function agnostic (there is only one function).