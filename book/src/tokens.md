# Token

`Token` define the type of note (e.g. XAN, ETH, BTC). Each token is identified by an address `tokenAddress` (the same way as user address identifies a user) and has its own VP `tokenVP`.

### Token VP
Each token has its own VP `tokenVP` that defines the conditions on which the token can be sent/received/etc (e.g. whitelist VP that only allows using the token a specified set of users). As with other VPs, it is required that the `tokenVP` of the tokens involved in a tx evaluated to `true`.

In Taiga, VPs are shielded, so instead of showing that `tokenVP` evaluates to `true` publicly, a ZK proof is created. To make sure that `tokenVP`  evaluates to `true`, an observer can verify the proof using  a verifier key `tokenVK`:
`verify(tokenVP_proof, tokenVK) = True`

### Token Address
Each token is identified by an address that is derived from its verifier key `tokenVK`:
`tokenAddress = Com(tokenVK)`


### Example
##### Create a token
In order to create a token, we need a token validity predicate. Let's create a trivial VP for now:
```rust
// Our VP defines (empty) constrains on input and output notes
pub struct TrivialValidityPredicate<CP: CircuitParameters> {
    input_notes: [Note<CP>; NUM_NOTE],
    output_notes: [Note<CP>; NUM_NOTE],
}
```
Our `TrivialValidityPredicate` needs to implement `Circuit` and `ValidityPredicate`:
```rust
// We implement the (empty) circuit corresponding to this VP
impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for TrivialValidityPredicate<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x00; 32];

    // Default implementation
    fn gadget(
        &mut self,
        _composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        // nothing
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 2
    }
}

// We implement the ValidityPredicate trait
impl<CP> ValidityPredicate<CP> for TrivialValidityPredicate<CP>
where
    CP: CircuitParameters,
{
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.input_notes
    }

    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
        &self.output_notes
    }

    fn custom_constraints(
        &self,
        _composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        _input_note_variables: &[ValidityPredicateInputNoteVariables],
        _output_note_variables: &[ValidityPredicateOutputNoteVariables],
    ) -> Result<(), Error> {
        Ok(())
    }
}
```
From this VP, we can create a token and compute its address:
```rust
use ark_std::test_rng;
use crate::token::Token;
use crate::circuit::validity_predicate::NUM_NOTE;
use crate::note::Note; 
use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
use crate::vp_description::ValidityPredicateDescription;
use ark_poly_commit::PolynomialCommitment;

type Fr = <CP as CircuitParameters>::CurveScalarField;
type PC = <CP as CircuitParameters>::CurvePC;

let mut rng = test_rng();
let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));

let mut vp = TrivialValidityPredicate::<CP> {
	input_notes,
	output_notes,
};

let vp_setup = PC::setup(vp.padded_circuit_size(), None, &mut rng).unwrap();
let desc_vp = ValidityPredicateDescription::from_vp(&mut vp, &vp_setup).unwrap();

let tok = Token::<CP>::new(desc_vp);

let _tok_addr = tok.address().unwrap();
```
It is also possible to create a dummy token (meaning that the VP description is simply a random element):
```rust
let mut rng = ark_std::test_rng();
let tok = Token::<CP>::dummy(&mut rng);
```
This example is taken from [this file](src/doc_test_simple_example.rs) and is reproducible with the command:
```
cargo test test_token_creation
```
From this token, we can create dummy notes of this specified token using the `dummy_from_token` function:
```rust
let note = Note::<CP>::dummy_from_token(tok, rng);
```
Note that with this `dummy_from_token` function, the owner of the note is a random user. We will see in the next section how to define a user.
