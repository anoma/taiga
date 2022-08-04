# Blinding

In the previous section, we explained how we bind the different proofs to the spent and created notes. In this section, we focus on the privacy of the verifier keys of these proofs.

Validity predicates are customizable by users and tokens. Moreover, the verifier keys are computed from the circuits and are visible by all the verifiers of the proof. These verifier keys are private information that leak privacy.

```
verifier key (public)-------
                            | -----> true/false
proof-----------------------
```
In order to get full privacy, we blind the verifier keys so that a proof can be checked against a verifier key or its blinded version.
```
vk --------------> randomized vk------
            |                         |
proof-------.----> true/false  <----.-
       |                            |
        ----------------------------
```
In this way, a verifier does not require the private verifier key and can check the proof against the blinded vk. Though, this verifer needs a proof that the blinded key comes from the actual verifier key. This binding is made using another commitment:
* `vk` is commited to `com_vk`
* `vk` is randomized into `blinded_vk`
From that, a proof of correct randomization is computed together with an opening of `com_vk`.
```
vk--------> blinded_vk-----> proof of blinding
     \
      com_vk---------------> proof of opening
```
This blinding is done for user's `sendVK` and `recVK` as well as for `tokenVK`.

## Example of blinding proof
First, we create a blinding circuit structure including the random values used for blinding:
```rust
let mut blinding_circuit =
      BlindingCircuit::<CP>::new(&mut rng, vp_desc, &pp, vp.padded_circuit_size()).unwrap();
```
As for `sendVP`, `recVP` and `TokenVP` proofs, we need a setup and prover/verifier keys:
```rust
let (pk_blind, vk_blind) = vp
      .compile_with_blinding::<PC>(&pp, &blinding_circuit.get_blinding())
      .unwrap();
let pp_blind = Opc::setup(blinding_circuit.padded_circuit_size(), None, &mut rng).unwrap();
```
From that, we can generate the blinding proof. Note that this is a bit expensive in practice:
```rust
let (proof, public_inputs) = blinding_circuit
      .gen_proof::<Opc>(&pp_blind, pk_p, b"Test")
      .unwrap();
```
From a proof, the verifier can check the public inputs against the blinded verifier key `vk_blind` (see [here](doc_examples/blinding.rs)), and verifiy the proof:
```rust
let verifier_data = VerifierData::new(vk, public_inputs);
verify_proof::<Fq, OP, Opc>(
    &pp_blind,
    verifier_data.key,
    &proof,
    &verifier_data.pi,
    b"Test",
)
.unwrap();
```