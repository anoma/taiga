# Taiga Spec

⚠️ Instantiations and the exact formulas are not stable ⚠ ️

## 1. Proving system

We use Halo2/IPA with [Pasta curves](https://github.com/zcash/pasta) developed by Zcash to instantiate our proving system.

### 1.1 Circuits
Let `C(x; w) ⟶ 0/1` be a circuit with up to `n` gates. The circuit is represented as polynomials over the chosen curve's **scalar field**, following [plonk-ish arithmetization](https://zcash.github.io/halo2/concepts/arithmetization.html). Commitments are generated over the curve's **base field**.

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
|__Prove__|`P(C, x, w) ⟶ π`|arithmetized over both $\mathbb{F}_p$ and $\mathbb{F}_q$|
|__Verify__|`V(desc_C, x, π) ⟶ 0/1`|arithmetized over both $\mathbb{F}_p$ and $\mathbb{F}_q$|

Does it apply to the action circuit?

## 2. Notes
Note is an immutable particle of the application state.

### 2.1 Note structure
|Variable|Description|
|-|-|
|`value_base`|`value_base = hash_to_curve(Poseidon(app_vk, app_data_static))`|
|`app_data_dynamic`|Commitment to the note's extra data|
|`v`|The quantity of fungible value (u64)|
|`nk_com`|`Poseidon(nk)`; commitment to the nullifier key that will be used to derive the note's nullifier|
|`ρ`| an old nullifier from the same Action description|
|`ψ`| the prf output of `ρ` and `rcm_note`|
|`is_merkle_checked`|dummy note flag|
|`rcm_note`| a random commitment trapdoor|

#### 2.1.1 Application-related fields

Each note has three fields with application data.

|Variable|Description|
|-|-|
|`app_vk`| Contains the application's main VP verifier key. Used to identify the application the note belongs to|
|`app_data_static`|Contains the application data that affects fungibility of the note. Along with the verifier key, it is used to derive note's value base|
|`app_data_dynamic`|Contains the application data that doesn't affect the fungibility of the note|

TODO: add examples of static and dynamic data

#### 2.1.2 Value base

Value base is used to distinguish note types. Notes with different value bases belong to different note types. The value base of the note is derived from two fields: `app_vk` and `app_data_static`.

|Variable|Description|
|-|-|
|`app_vk`|Verifying key of the VP circuit|
|`app_data_static`|Application data that influences note's fungibility. Notes with the same `app_vk` but different `app_data_static` are not fungible|

##### 2.1.2.1 Value commitment

Used to ensure balance across the notes in an Action.

One-type value commitment computation (orchard, p. 93, homomorphic pedersen commitment):

$[v^{old} - v^{new}]VB + [rcv]R$

Multiple types value commitment computation:

$cv = [v^{old}]VB^{old} - [v^{new}]VB^{new} + [rcv]R$

### 2.3 Note commitment

Note commitments are stored in a global commitment tree. The global commitment tree contains commitments to all of the notes ever existed. Adding a note's commitment to the commitment tree announces the creation of the note. The notes are never removed from the tree. Instead, notes are invalidated by revealing their nullifiers.

|Name|Type|Description|
|-|-|-|
|`cm` | Pallas point ($\mathbb F_p$, $\mathbb F_p$)|$cm = \mathrm{NoteCom}(note, rcm\_note)$|

### 2.5 Nullifier
Note nullifiers are stored in a global nullifier set. Adding a note's nullifier to the set invalidates the note. We use the same nullifier derivation algorithm as in Orchard: $\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = \mathrm{Extract}([PRF_{nk}(ρ) + ψ \mod{q}]K + cm)$.

|Name|Type|Description|
|-|-|-|
|`nf`|$\mathbb F_p$|$nf = \mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm)$
|`nk` | $\mathbb F_p$ | the nullifier deriving key|
|`ρ`| $\mathbb{F}_p$ | an old nullifier|
|`ψ`| $\mathbb{F}_p$ | $PRF_{rcm\_note}(ρ)$ -- should it be the same as in zcash?|
|`cm` | Pallas point($\mathbb F_p$, $\mathbb F_p$) | note commitment |
|`K`|Pallas point($\mathbb F_p$, $\mathbb F_p$)| a fixed base generator of the inner curve|
|`Extract` | $(\mathbb F_p$, $\mathbb F_p) \rightarrow \mathbb F_p$ | the $x$ coordinate of a (inner curve) point|

#### 2.5.1 Nullifier deriving key `nk`

The nullifier key for the note is derived when the note is created and is only known to the note's owner (or anyone the owner reveals the key to). Knowledge of the note's nullifier key is necessary (but not sufficient) to create the note's nullifier and invalidate the note.

⚠️ Not implemented

$nk = PRF_{r}(\mathrm{PERSONALIZATION\_NK}) \mod{q}$, where `PERSONALIZATION_NK = "Taiga_PRF_NK"` and `r` is a random value.


## 3. Circuits
### 3.1 The ction Circuit

The action circuit `ActionCircuit(x; w)` checks that the Taiga rules are being followed by a proposed transaction. The check is performed per partial transaction. The circuit is arithmetized over $\mathbb{F}_p$. 

Note: the action circuit doesn't contain all of the checks required. If the check can be done outside of the circuit without revealing any sensitive information, it is performed outside the circuit.

The Action circuit performs checks over `n` inputs and `n` output notes. Currently, `n = 2`. 

#### Inputs
Public inputs (`x`):
1. `rt` - the root of the commitment Merkle tree
2. `nf` - input note nullifier; commits to note application type, value, and data
3. `com_vp_in` - input note's application VP commitment
4. `cm` - output note commitment
5. `com_vp_out` - output note's application VP commitment

Private inputs (`w`):
1. `in_note = (value_base, v, nk_com, ρ, ψ, is_merkle_checked, rcm_note)` - input note opening 
2. `(com(vp_vk), rcm_vp_vk)` - opening of `com_vp_in`
3. `out_note = (value_base, v, nk_com, ρ, ψ, is_merkle_checked, rcm_note)` - output note opening
4. `(com(vp_vk), rcm_vp_vk)` - opening of `com_vp_out`

Note: opening of a parameter is every field used to derive the parameter

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

### 3.1 Validity Predicate (VP) circuits

Validity predicate is a circuit derived per application. It contains the application's logic. Validity predicates take `n` input and `n` output notes, are represented as Halo2 circuits `VP(x; w) ⟶ 0/1` and arithmetized over $\mathbb{F}_p$.

- `VPCommit(vp, rcm_vp) = Com( Com_q(desc_vp), rcm_vp)`

ToDO: add reasoning for complex commitment list
TODO: add how vps check that the note belongs to them

#### Inputs

Public inputs (`x`):
- `nf_1, …, nf_n` - input note nullifiers
- `cm_1, …, cm_n` - output note commitments
- `ce_1, …, ce_n` - encrypted output notes

Private inputs (`w`):
- `old_note_1, …, old_note_m` - input notes
- `new_note_1, …, new_note_n` - output notes
- custom private inputs

#### Checks
As opening of the notes are private parameters, to make sure that notes that the VP received indeed the ones that correspond to the public parameters, VP must check:

1. input note nullifier integrity: for each `i ∈ {1, …, m}`, `nf_i = DeriveNullifier_nk(ρ, ψ, cm)`
2. Output note commitment integrity: for each `i ∈ {1, …, n}`, `cm_i = NoteCommit(note, rcm_note)`
3. Encrypted note integrity: for each `i ∈ {1, …, n}`, `ce_i = Encrypt(note, ek)`

Note: encryption can be customized per application. Some applications might encrypt more fields, others - less. It does leak some information

Note: to determine whether a note belongs to the application or not, Taiga marks the note commitments (for output notes) or nullifiers (for input notes) of the notes.

All other constraints enforced by VP circuits are custom.


## Instantiations
|Function|Instantiation|Domain/Range|Description|
|-|-|-|-|
|Nullifier PRF|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|$\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = \mathrm{Extract}([PRF_{nk}(ρ) + ψ \mod{q}]K + cm)$|
|`nk` commitment|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|`Com(nk) = Poseidon(nk, user_derived_key)`; used to protect `nk` stored in a note. `user_derived_key` is currently not used
|`nk` PRF|Blake2s|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|`nk = PRF(nk, r)`| Used to derive `nk`; currently not implemented
|address|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$| `address = Poseidon(app_data_dynamic, nk_com)`; compresses the data fields that contain some ownership information
|`NoteCommit`|[Sincemilla](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html)|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|
|`VPCommit`|Blake2s|-|Efficient over both $\mathrm{F}_p$ and $\mathrm{F}_q$
|Value base derivation|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|`value_base = hash_to_curve(Poseidon(app_vk, app_data_static))`; compresses the fields related to the resource type
|`ValueCommit`|Pedersen-like|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|`cv = (v_i * VB_i - v_o * VB_o) + r[R]`, `VB_x` - value base of a note
|VE|DH + Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$| `ek = DH(recv.pk, sender.sk)`, `ce = Poseidon(note, ek)`

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
