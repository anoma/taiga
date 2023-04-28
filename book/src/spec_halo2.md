# Taiga Spec Working Draft

To be edited as design changes. Please make changes as necessary. Keep it **concise** and **precise**.

## 1. Proving system

We use Halo2/IPA with Pasta curves developed by Zcash to instantiate our proving system.

### 1.1 Elliptic curves
||Name|Scalar field| Base field|Purpose|Instantiation|
|-|-|-|-|-|-|
|$E_I$|Inner curve|$\mathbb{F}_q$|$\mathbb{F}_p$|ECC gadget| Pallas
|$E_M$|Main curve|$\mathbb{F}_p$|$\mathbb{F}_q$|Action and VP circuits| Vesta|
|$E_O$|Outer curve|$\mathbb{F}_q$|$\mathbb{F}_p$|Accumulation circuit| Pallas|

### 1.2 Polynomial commitment scheme $Com$
- $d$ is the bounded degree of any polynomial in the scheme
- polynomials are defined over the scalar field of the curve $E_M$ ($\mathbb{F}_p$)
- commitments are points on $E_M$ ($\mathbb{F}_q$)
- $Com(..): \mathbb{F}_p \rarr \mathbb{F}_q$

### 1.3 Circuit
- `C(x; w) ⟶ 0/1`
- upto `n` fan-in 3 (or 4) addition / multiplication / lookup gates over $\mathbb{F}_p$
- Following [plonk-ish arithmetization](https://zcash.github.io/halo2/concepts/arithmetization.html), `C(x; w)` can be turned into polynomials over $\mathbb{F}_p$

### 1.4 Proving system interfaces
||Interface|Description|
|-|-|-|
|__Preprocess__|`preproc(C) ⟶ desc_C`|`C` is turned into a *circuit description* which is a sequence of polynomial commitments|
|__Prove__|`P(C, x, w) ⟶ π`|arithmetized over $\mathbb{F}_p$ and $\mathbb{F}_q$|
|__Verify__|`V(desc_C, x, π) ⟶ 0/1`|arithmetized over $\mathbb{F}_p$ and $\mathbb{F}_q$|

### 1.5 Potential features
#### Accumulation (of proofs / verifier circuit)

Definitions from Section 4.1 of [BCMS20](https://eprint.iacr.org/2020/499.pdf), and specializing to their Definition 4.2 for Plonk verifiers.

||Interface|Description|
|-|-|-|
|__Accumulation Prover__|`AccP(acc, desc_C, x, π) ⟶ (acc', aπ)` ??|over $\mathbb{F}_p$ and $\mathbb{F}_q$|
|__Accumulation Verifier__|`AccV(acc, acc', aπ, desc_C, x, π) ⟶ 0/1` ??|over $\mathbb{F}_q$ ?|
|__Accumulation Decider__|`AccD(acc) ⟶ 0/1`|over $\mathbb{F}_q$ ?|


## 2. Abstractions
### 2.1 Data types
- Input / output of each abstract interface, e.g. `Com, Com_q`, defines a distinct type.
- Each distinct data field defines a type, e.g. `v, data, asset_type`.
- Data types are linked via interface definition and usage as required, e.g. `v` is of the same type as the first input to `Com_v`.
- All data types have **fixed length**.

### 2.2 Commitments

We blend commitments into a single abstract interface.

|Commitment|Efficient over|Description|
|-|-|-|
|`Com_q(...) ⟶ com`|$\mathbb{F}_q$||
|`Com_r(...) ⟶ com`|$\mathbb{F}_p$||
|`Com(...) ⟶ com`|**both** $\mathbb{F}_q$ and $\mathbb{F}_p$||

#### 2.3 Binding & hiding
Commitments are binding by default (i.e. can be instantiated with hash). If we want hiding (possibly across differnt commitments), we add `rcm` explicitly.

### 2.4 Validity predicates
|Name||Description|
|-|-|-|
|VP description|`desc_vp = preproc(vp)`|generate pk, vk, CRS|
|VP commitment|`VPCom(desc_vp; rcm_com_vp) := Com( Com_q(desc_vp), rcm_com_vp)`||

### 2.5 Note
#### 2.5.1 Note fields
|Variable|Type|Description|
|-|-|-|
|`note_type`| Pallas point ($\mathbb{F}_p$, $\mathbb{F}_p$) | Value base. `note_type = poseidon_to_curve(Poseidon(app_vk, app_data_static))`|
|`app_data_dynamic`| $\mathbb{F}_p$ |Commitment to the note's dynamic data|
|`v`| `u64` ($\mathbb F_p$ element in circuit) |The quantity of fungible value|
|`nk_com`|$\mathbb{F}_p$|`Poseidon(nk)`|
|`ρ`| $\mathbb{F}_p$ | an old nullifier from the same Action description|
|`ψ`| $\mathbb{F}_p$ | the prf output of `ρ` and `rcm_note`|
|`is_merkle_checked`|bool|dummy note flag|
|`rcm_note`| $\mathbb{F}_q$| a random commitment trapdoor|

#### 2.5.2 Value base
TODO: clarify the type of app_vk

|Variable|Type|Description|
|-|-|-|
|`app_vk`|?|Verifying key of the application circuit|
|`app_data_static`|$\mathbb{F}_p$| application data used to derive note's type|

#### 2.5.3 Note commitment

|Name|Type|Description|
|-|-|-|
|`cm` | Pallas point ($\mathbb F_p$, $\mathbb F_p$)|$cm = \mathrm{NoteCom}(note, rcm\_note)$|

TODO: same as Orchard?

### 2.6 Nullifier deriving key `nk`

Note: not implemented (yet?)

|Name|Type|Description|
|-|-|-|
|$nk = PRF_{random}(\mathrm{PERSONALIZATION\_NK}) \mod{q}$|$\mathbb{F}_q$|`nk` is randomly generated (by the user)|
|random||random value|
|PERSONALIZATION_NK| string| set to `"Taiga_PRF_NK"`||

### 2.7 Nullifier

Use the nullifier derivation as in Orchard: $\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = \mathrm{Extract}([PRF_{nk}(ρ) + ψ \mod{q}]K + cm)$

|Name|Type|Description|
|-|-|-|
|`nf`|$\mathbb F_p$|$nf = \mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm)$
|`nk` | $\mathbb F_p$ | the nullifier deriving key|
|`ρ`| $\mathbb{F}_p$ | an old nullifier|
|`ψ`| $\mathbb{F}_p$ | $PRF_{rcm\_note}(ρ)$ -- should it be the same as in zcash?|
|`cm` | Pallas point($\mathbb F_p$, $\mathbb F_p$) | note commitment |
|`K`|Pallas point($\mathbb F_p$, $\mathbb F_p$)| a fixed base generator of the inner curve|
|`Extract` | $\mathbb F_p$ | the $x$ coordinate of a (inner curve) point|


## 3. ZK Circuits

### Validity Predicate (VP) circuits

- Arithmetized over $\mathbb{F}_p$.
- Represented as a Halo2 circuit `VP(x; w) ⟶ 0/1`.
- Expects `m` notes input and `n` notes created. `m` and `n` could be different for each VP involved in a Taiga transaction.

#### Inputs
Public inputs (`x`):

- `nf_1, …, nf_m` - input note nullifiers
- `cm_1, …, cm_n` - created note commitments

Private inputs (`w`):
- `old_note_1, …, old_note_m` - input notes
- `new_note_1, …, new_note_n` - created notes
- custom private inputs

#### Checks
Each VP must perform some standard checks to make sure the note binding is correct:
2. input note nullifier integrity: for each `i ∈ {1, …, m}`, `nf_i = DeriveNullifier_nk(ρ, ψ, cm)`
3. Output note commitment integrity: for each `i ∈ {1, …, n}`, `cm_i = NoteCommit(note, rcm_note)`

TODO: explain why we need these checks

All other constraints enforced by VP circuits are custom.

Note: encrypted note integrity is checked in the action circuit (doesn't have to be here?)

### Action Circuit

- Arithmetized over $\mathbb{F}_p$.
- Represented as a Halo2 circuit `ActionCircuit(x; w)`.

#### Inputs
Public inputs (`x`):
- `rt` - the root of the commitment Merkle tree
- `ce` - encrypted output note
- input note related:
    - `nf` - input note nullifier; commits to note application type, value, and data
    - `com_vp_app` - application VP commitment
- output note related:
    - `cm` - output note commitment
    - `com_vp_app` - application VP commitment

Private inputs (`w`):
- input note related:
    - `note = (note_type, app_data_dynamic, v, nk_com, ρ, ψ, is_merkle_checked, rcm_note)`
    - `com_vp_app` opening of the input note:
        - `Com_q(desc_vp_app)`, 
        - `rcm_com_vp_app` 
- output note related:
    - `note = (note_type, app_data_dynamic, v, nk_com, ρ, ψ, is_merkle_checked, rcm_note)`
    - `com_vp_app` opening of the output note:
        - `Com_q(desc_vp_app)`, 
        - `rcm_com_vp_app`

#### Checks
- For input note:
    - If `is_merkle_checked = true`, check that the note is a valid note in `rt`: there is a path in Merkle tree with root `rt` to a note commitment `cm` that opens to `note`
    - Nullifier integrity: `nf = DeriveNullier_nk(note)`.
    - Application VP integrity: `com_vp_app = Com(Com_q(desc_vp_app), rcm_com_vp_app)`
- For output note:
    - Commitment integrity(output note only): `cm = NoteCom(note, rcm_note)`
    - Application VP integrity: `com_vp = Com(Com_q(desc_vp_app), rcm_com_vp_app)`
    - Encryption check: `ce = NoteEnc(note)`

TODO: to avoid the situation when the user spends note that isn't checked in the merkle tree, trying to output a valid note, the VP should take this into account? Check that the note isn't dummy
TODO: cv check
TODO: add conditional `is_merkle_checked` checks

## Instantiations
|Function|Description|Instantiation|
|-|-|-|
|nullifier PRF||Poseidon|
|nk commitment||Poseidon|
|nk PRF||Blake2s|
|address||Poseidon (f_p -> f_p)??|
|note commitment ($Com_r$)||Sincemilla (f_p -> f_p)|
|VP commitment (Com)||Blake2s|
|VE||DH + Poseidon|
|hash to curve|||

## Taiga Application
    
For each epoch the state consists of:
- Merkle tree, $MT$, of note commitments with root `rt`
    - Supporting add: $MT.add(cm, ce)$
    - Only `cm` is hashed in derivation of `rt`, note encryption `ce` is simply stored alongside `cm`
- Set of input note nullifiers, $NF$
    - Supporting add: $NF.add(nf)$
    - Supports memership checks
    
The state should make past `rt` accessible as well

### Taiga `tx`
A Taiga transaction contains:
- `k` actions, each of which contains one input and one output note. Actions include:
    - `π_action` - `ActionCircuit` proof
    - `(rt, nf, cm, com_vp_input, com_vp_output, ce)` - `ActionCircuit` public input 

TODO: Add partial transactions. Can we not have partial transactions in a Taiga tx?

#### Validity of `tx`
A transaction `tx` is valid if:
1. For each $i$-th action:
    - [if `is_merkle_checked = true`] `rt_i` is a valid Merkle root from current or past epoch.
    - `Verify(desc_ActionCircuit, ActionPublicInput, π_action_i) = True`
2. For each VP:
    - `Verify'(desc_VP, com_vp, π_vp) = True`
    
#### Processing of `tx`
A valid Taiga transaction `tx` induces a state change as follows:
1. For each `nf` ∈ `NF_tx`: $NF.add(nf)$
1. For each `cm` ∈ `CM_tx` with associated `ce`: $MT.add(cm, ce)$
    - `rt` is not updated for operation
1. Re-compute `rt` of $MT$


## Halo2 Accumulation
TBD
