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
|Variable|Type|Description|
|-|-|-|
|`app_vk`|$\mathbb{F}_p$ (compressed)|Verifying key of the application circuit. Compressed into a Pallas point|
|`app_data_static`|$\mathbb{F}_p$| application data used to derive note's type|

#### 2.5.3 Note commitment

|Name|Type|Description|
|-|-|-|
|`cm` | Pallas point ($\mathbb F_p$, $\mathbb F_p$)|$cm = \mathrm{NoteCom}(note, rcm\_note)$. `NoteCom`|

TODO: which fields to commit to?

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
- `ce_1, …, ce_n` - encrypted output notes


Private inputs (`w`):
- `old_note_1, …, old_note_m` - input notes
- `new_note_1, …, new_note_n` - created notes
- custom private inputs

#### Checks
As opening of the notes are private parameters, to make sure that notes that the VP received indeed the ones that correspond to the public parameters, VP must check:

1. input note nullifier integrity: for each `i ∈ {1, …, m}`, `nf_i = DeriveNullifier_nk(ρ, ψ, cm)`
2. Output note commitment integrity: for each `i ∈ {1, …, n}`, `cm_i = NoteCommit(note, rcm_note)`
3. Encrypted note integrity: for each `i ∈ {1, …, n}`, `ce_i = Encrypt(note, ek)`

Note: encryption can be customized per application. Some applications might encrypt more fields, others - less. It does leak some information

All other constraints enforced by VP circuits are custom.

### Action Circuit

- Arithmetized over $\mathbb{F}_p$.
- Represented as a Halo2 circuit `ActionCircuit(x; w)`.

#### Inputs
Public inputs (`x`):
- `rt` - the root of the commitment Merkle tree
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
- Value commitment integrity: `cv = ValueCommit(v_in - v_out, rcv)` 

## Instantiations
|Function|Instantiation|Description|
|-|-|-|
|Nullifier PRF|Poseidon|$\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = \mathrm{Extract}([PRF_{nk}(ρ) + ψ \mod{q}]K + cm)$|
|`nk` commitment|Poseidon|`Com(nk) = Poseidon(nk, user_derived_key)`; used to protect `nk` stored in a note. `user_derived_key` is currently not used
|`nk` PRF|Blake2s|`nk = PRF_r(...)`| Used to derive `nk`
|address|Poseidon| `address = Poseidon(app_data_dynamic, nk_com)`; compresses the data fields that contain some ownership information
|`NoteCommit`|[Sincemilla](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html)|
|`VPCommit`|Blake2s|Efficient over both $\mathrm{F}_p$ and $\mathrm{F}_q$
|Value base derivation|Poseidon|`value_base = hash_to_curve(Poseidon(app_vk, app_data_static))`; compresses the fields related to the resource type
|`ValueCommit`|Pedersen-like|`cv = (v_i * VB_i - v_o * VB_o) + r[R]`, `VB_x` - value base of a note
|VE|DH + Poseidon| `ek = DH(recv.pk, sender.sk)`, `ce = Poseidon(note, ek)`

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
- a set of `k` partial transactions: `[ptx_1, .., ptx_k]`
- a binding signature

### Taiga `ptx`

Each Taiga `ptx` contains 2 input and 2 output notes. Each of the notes requires at least one VP to be satisfied, resulting in at most 4 VP proofs per `ptx`. If the same VP controls 2+ notes in a `ptx`, the VP is called just once per `ptx`, reducing the total amount of non-dummy proofs. 

Note: it is possible that a VP requires checks of other VPs in order to be satisfied. In that case, the total amount of VPs checked could be more than 4, but we can count such check as a single check.

Note: For security reasons, it might make sense to require a minimal amount of proofs attached to be 4 and attach dummy proofs if needed.

Each Taiga ptx contains:
- `2` actions:
    - `π_action` - proof of the action
    - `(rt, nf, cm, com_vp_input, com_vp_output, ce)` - public input
- for each input note:
    - `π_VP` proof
    - VP public input
    - VP vk
    - `extra_VP_vk` (if the "main" VP requires additional VPs to be checked) 
- for each output note:
    - `π_VP` proof
    - VP public input
    - VP vk
    - `extra_VP_vk` (if the "main" VP requires additional VPs to be checked)

#### Validity of `tx`
A transaction `tx` is valid if:
1. For each $i$-th action:
    - [if `is_merkle_checked = true`] `rt_i` is a valid Merkle root from current or past epoch.
    - `Verify(ActionVK, ActionPublicInput, π_action_i) = True`
2. For each VP:
    - `Verify'(VP_VK, VPPublicInput, π_VP) = True`
3. Balance check: the binding signature is valid
    
#### Processing of `tx`
A valid Taiga transaction `tx` induces a state change as follows:
1. For each `nf` ∈ `NF_tx`: $NF.add(nf)$
1. For each `cm` ∈ `CM_tx` with associated `ce`: $MT.add(cm, ce)$
    - `rt` is not updated for operation
1. Re-compute `rt` of $MT$


## Halo2 Accumulation
TBD
