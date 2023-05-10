# Taiga Spec

⚠️ Instantiations and exact formulas are not stable ⚠ ️

## 1. Proving system

We use Halo2/IPA with [Pasta curves](https://github.com/zcash/pasta) developed by Zcash to instantiate our proving system.

### 1.1 Circuits
Let `C(x; w) ⟶ 0/1` be a circuit with up to `n` gates. The circuit is represented as polynomials over the chosen curve's scalar field, following [plonk-ish arithmetization](https://zcash.github.io/halo2/concepts/arithmetization.html). Commitments are generated over the curve's base field.

### 1.2 Elliptic curves
||Name|Scalar field| Base field|Purpose|Instantiation|
|-|-|-|-|-|-|
|$E_I$|Inner curve|$\mathbb{F}_q$|$\mathbb{F}_p$|ECC gadget| [Pallas](https://github.com/zcash/pasta#pallasvesta-supporting-evidence)
|$E_M$|Main curve|$\mathbb{F}_p$|$\mathbb{F}_q$|Action and VP circuits| Vesta|
|$E_O$|Outer curve|$\mathbb{F}_q$|$\mathbb{F}_p$|Accumulation circuit| Pallas|

### 1.3 Proving system interfaces
||Interface|Description|
|-|-|-|
|__Preprocess__|`preproc(C) ⟶ desc_C`|`C` is turned into a *circuit description*, which is all data the verifier needs to verify a proof. It includes the verifier key, but not only that.|
|__Prove__|`P(C, x, w) ⟶ π`|arithmetized over $\mathbb{F}_p$ and $\mathbb{F}_q$|
|__Verify__|`V(desc_C, x, π) ⟶ 0/1`|arithmetized over $\mathbb{F}_p$ and $\mathbb{F}_q$|


## 2. Notes
#### 2.1 Note structure
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

#### 2.2 Value base

|Variable|Type|Description|
|-|-|-|
|`app_vk`|$\mathbb{F}_p$ (compressed)|Verifying key of the application circuit. Compressed into a Pallas point|
|`app_data_static`|$\mathbb{F}_p$| application data used to derive note's type|

#### 2.3 Note commitment

|Name|Type|Description|
|-|-|-|
|`cm` | Pallas point ($\mathbb F_p$, $\mathbb F_p$)|$cm = \mathrm{NoteCom}(note, rcm\_note)$|

TODO: which fields to commit to?

### 2.4 Nullifier deriving key `nk`
Note: not implemented (yet?)

|Name|Type|Description|
|-|-|-|
|$nk = PRF_{random}(\mathrm{PERSONALIZATION\_NK}) \mod{q}$|$\mathbb{F}_q$|`nk` is randomly generated (by the user)|
|random||random value|
|PERSONALIZATION_NK| string| set to `"Taiga_PRF_NK"`||

### 2.5 Nullifier

Use the nullifier derivation as in Orchard: $\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = \mathrm{Extract}([PRF_{nk}(ρ) + ψ \mod{q}]K + cm)$

|Name|Type|Description|
|-|-|-|
|`nf`|$\mathbb F_p$|$nf = \mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm)$
|`nk` | $\mathbb F_p$ | the nullifier deriving key|
|`ρ`| $\mathbb{F}_p$ | an old nullifier|
|`ψ`| $\mathbb{F}_p$ | $PRF_{rcm\_note}(ρ)$ -- should it be the same as in zcash?|
|`cm` | Pallas point($\mathbb F_p$, $\mathbb F_p$) | note commitment |
|`K`|Pallas point($\mathbb F_p$, $\mathbb F_p$)| a fixed base generator of the inner curve|
|`Extract` | $(\mathbb F_p$, $\mathbb F_p) \rightarrow \mathbb F_p$ | the $x$ coordinate of a (inner curve) point|


## 3. ZK Circuits

### Validity Predicate (VP) circuits
- Validity predicate is a custom circuit 
- `VPCommit(vp, rcm_vp) = Com( Com_q(desc_vp), rcm_vp)`
TBD

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
    - `com_vp` opening of the input note
- output note related:
    - `note = (note_type, app_data_dynamic, v, nk_com, ρ, ψ, is_merkle_checked, rcm_note)`
    - `com_vp` opening of the output note

#### Checks
- For input note:
    - If `is_merkle_checked = true`, check that the note is a valid note in `rt`: there is a path in Merkle tree with root `rt` to a note commitment `cm` that opens to `note`
    - Nullifier integrity: `nf = DeriveNullier_nk(note)`.
    - Application VP integrity: `com_vp = VPCommit(vp, rcm_vp)`
- For output note:
    - Commitment integrity(output note only): `cm = NoteCom(note, rcm_note)`
    - Application VP integrity: `com_vp = VPCommit(vp, rcm_vp)`
    - Value base integrity: TBD (similarly to the MASP, we only check vb for output notes)
- Value commitment integrity: `cv = ValueCommit(v_in - v_out, rcv)` 

## Instantiations
|Function|Instantiation|Domain/Range|Description|
|-|-|-|-|
|Nullifier PRF|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|$\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = \mathrm{Extract}([PRF_{nk}(ρ) + ψ \mod{q}]K + cm)$|
|`nk` commitment|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|`Com(nk) = Poseidon(nk, user_derived_key)`; used to protect `nk` stored in a note. `user_derived_key` is currently not used
|`nk` PRF|Blake2s|$\mathrm{F}_p \rightarrow \mathrm{F}_?$|`nk = PRF(nk, r)`| Used to derive `nk`; currently not implemented
|address|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$| `address = Poseidon(app_data_dynamic, nk_com)`; compresses the data fields that contain some ownership information
|`NoteCommit`|[Sincemilla](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html)|$\mathrm{F}_p \rightarrow \mathrm{F}_?$|
|`VPCommit`|Blake2s|-|Efficient over both $\mathrm{F}_p$ and $\mathrm{F}_q$
|Value base derivation|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|`value_base = hash_to_curve(Poseidon(app_vk, app_data_static))`; compresses the fields related to the resource type
|`ValueCommit`|Pedersen-like|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|`cv = (v_i * VB_i - v_o * VB_o) + r[R]`, `VB_x` - value base of a note
|VE|DH + Poseidon|$\mathrm{F}_? \rightarrow \mathrm{F}_?$| `ek = DH(recv.pk, sender.sk)`, `ce = Poseidon(note, ek)`

## The Taiga Application
    
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
    - desc_VP
    - `extra_VP_vk` (if the "main" VP requires additional VPs to be checked) 
- for each output note:
    - `π_VP` proof
    - VP public input
    - desc_VP
    - `extra_desc_VP` (if the "main" VP requires additional VPs to be checked)

#### Validity of `tx`
A transaction `tx` is valid if:
1. For each $i$-th action:
    - [if `is_merkle_checked = true`] `rt_i` is a valid Merkle root from current or past epoch.
    - `Verify(desc_Action, ActionPublicInput, π_action_i) = True`
2. For each VP:
    - `Verify'(desc_VP, VPPublicInput, π_VP) = True`
3. Balance check: the binding signature is valid
    
#### Processing of `tx`
A valid Taiga transaction `tx` induces a state change as follows:
1. For each `nf` ∈ `NF_tx`: $NF.add(nf)$
1. For each `cm` ∈ `CM_tx` with associated `ce`: $MT.add(cm, ce)$
    - `rt` is not updated for operation
1. Re-compute `rt` of $MT$


## Halo2 Accumulation
TBD
