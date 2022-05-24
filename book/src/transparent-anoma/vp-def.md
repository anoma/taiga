# Validity predicate definition

A validity predicate can be seen as rules to be followed by a structure. In Anoma, each user can specify its own rules. In practice, we compute arithmetic circuits, meaning that the rules are additions and multiplications of integers.

## Example 1. a Pythagorean circuit.
Suppose that we have a pythagorean triple `(a,b,c)`. We can consider a validity predicate that checks the equation `a² + b² == c²`.

## Example 2. Signature verification.
Given a message signed by a user using the ECDSA algorithm, the signature verification VP describes all the computations needed to verify an ECDSA signature. It involves a hash function, the elliptic curve group law and a modular reduction. All these computations are additions and multiplications that can be described into a circuit.

In the next section, we detail three examples of validity predicates in the context of Anoma.