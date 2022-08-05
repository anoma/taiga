# Implementation choices

## Elliptic curves
We use the PLONK construction for our zero-knowledge proofs. For this version, we use the KZG polynomial commitment scheme, meaning that we build the proof computation on a pairing-friendly curve. We use three curves for our implementation:
* The main curve where most of the proofs are computed.
* The inner curve is not used for the proof but for assertions to be proved. The base field corresponds to the scalar field of the main curve, so that arithmetic on this curve can be translated into a circuit of the main curve.
* The outer curve whose scalar field is the base field of the main curve. In this way, we can build proofs for the main curve arithmetic. In particular, we compute the randomization of the verifier keys proof on this curve.

## Commitment choices
We use several commitments in Taiga. We specify what choices we made for now:
* We use hash commitment so that we can build circuit using ZK-friendly hash function.
* Hash function image is a field that needs to be chosen with the binding we need.
* For example, the note commitment needs to be done over the main curve scalar field because we want to bind the token address (one of the input of the note commitment) with the token address integrity (the fact that token_VK is binded to the token address). This token address integrity is done over main curve scalar field. WHY?
* The blinding 
  we can bind the input of the hash (e.g. the token address) with the circuit corresponding to the  we open the note token address,  we bind it with the verifier The commitment field  are done over the main curve scalar field, except the commitment for Verifier key are over the main curve base field.

|Commitment| Field | Why?|
|-|-|-|
|Token address|MainCurve::ScalarField| because it is the most efficient choice|
|User address|MainCurve::ScalarField| because it is the most efficient choice (and uses `nk`)|
|Note commitment|MainCurve::ScalarField| because it is binded to the token address|
|...|...|...|

