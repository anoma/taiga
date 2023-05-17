# Taiga Spec Draft

⚠️ Instantiations and the exact formulas might be not stable ⚠ ️

## 1. Proving system

We use Halo2/IPA with [Pasta curves](https://github.com/zcash/pasta) developed by Zcash to instantiate our proving system.

### 1.1 Circuits
Let `C(x; w) ⟶ 0/1` be a circuit with up to `m` gates. The circuit is represented as polynomials over the chosen curve's **scalar field**, following [plonk-ish arithmetization](https://zcash.github.io/halo2/concepts/arithmetization.html). Commitments are generated over the curve's **base field**.

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
|__Prove__|`P(C, x, w) ⟶ π`||
|__Verify__|`V(desc_C, x, π) ⟶ 0/1`||

## 2. Notes
Note is an immutable particle of the application state.

### 2.1 Note structure
|Variable|Type|Description|
|-|-|-|
|`value_base`|Pallas point|value base represents the note type|
|`app_data_dynamic`||Commitment to the note's extra data|
|`v`|${0..2^{64} - 1}$|The quantity of fungible value|
|`nk_com`||commitment to the nullifier key that will be used to derive the note's nullifier|
|`ρ`|$\mathbb{F}_p$| an old nullifier from the same Action description (see Orchard)|
|`ψ`|$\mathbb{F}_p$|the prf output of `ρ` and `rcm_note` (see Orchard)|
|`is_merkle_checked`|bool|dummy note flag|
|`rcm_note`|${0..2^{255} - 1}$| a random commitment trapdoor|

#### 2.1.1 Application-related fields

Each note has three fields with application data.

|Variable|Type|Description|
|-|-|-|
|`app_vk`|| Contains the application's main VP verifier key. Used to identify the application the note belongs to|
|`app_data_static`||Contains the application data that affects fungibility of the note. Along with `desc_app`, it is used to derive note's value base||
|`app_data_dynamic`||Contains the application data that doesn't affect the fungibility of the note|

#### Value base

Value base is used to distinguish note types. Notes with different value bases have different note types. The value base of a note is derived from two fields: `desc_app` and `app_data_static`.

`value_base = PRF_vb(desc_app, app_data_static)`



#### Value commitment

Used to ensure balance across the notes in an Action.

One-type value commitment computation (Orchard, p. 93, homomorphic pedersen commitment):

$[v^{in} - v^{out}]VB + [rcv]R$

Multiple types value commitment computation:

$cv = [v^{in}]VB^{in} - [v^{out}]VB^{out} + [rcv]R$

|Variable|Type|Description|
|-|-|-|
|$v^{in}$|${0..2^{64} - 1}$|Input note's value|
|$v^{out}$|${0..2^{64} - 1}$|Output note's value|
|$VB^{in}$|Pallas point|Input note's value base|
|$VB^{out}$|Pallas point|Output note's value base|
|R|Pallas point|Randomness base, fixed|
|`rcv`|${0..2^{255} - 1}$|Value commitment trapdoor|
|`cv`|Pallas point|Value commitment|

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
|`cm` | Pallas point| note commitment |
|`K`|Pallas point| a fixed base generator of the inner curve|
|`Extract` | $(\mathbb F_p$, $\mathbb F_p) \rightarrow \mathbb F_p$ | the $x$ coordinate of an (inner curve) point|

#### 2.5.1 Nullifier deriving key `nk`

The nullifier key for the note is derived when the note is created and is only known to the note's owner (or anyone the owner reveals the key to). Knowledge of the note's nullifier key is necessary (but not sufficient) to create the note's nullifier and invalidate the note.

⚠️ Not implemented

$nk = PRF_{r}(\mathrm{PERSONALIZATION\_NK}) \mod{q}$, where `PERSONALIZATION_NK = "Taiga_PRF_NK"` and `r` is a random value.

### 2.6 Verifiable encryption

Encryption is used for in-band distribution of notes. Encrypted notes are stored on the blockchain, the receiver can scan the blockhcain trying to decrypt the notes and this way to find the notes that were sent to them.

We want the encryption to be verifiable to make sure the receiver of the notes can decrypt them. In other systems like Zcash it doesn't make sense to send the wrong notes to the receiver (essentially burning them), but in Taiga as the notes are created not by the sender but an intermediate party (solver) 


We use the combination of DH key exchange with Poseidon symmetric encryption.
```
sk = DH(pk_recv, sk_send)
ce = Poseidon(sk, note)
```

Not all of the note fields require encryption (e.g. note commitment), and the encrypted fields may vary depending on the application.


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
    - Value base integrity: `vb = PRF_vb(desc_app, app_data_static)`
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


## 4. Circuit Accumulation
TBD: Halo2 accumulation

### 5. Binding signature
Binding signature is used to make sure the transaction is balanced. Value commitments produced in each partial transaction are accumulated and checked against the commitment to the expected net value change. The value change might be zero, indicating that the whole transaction was done in the schielded space, or non-zero, indicating that some value came from/to the transparent space. We use the same binding signature mechanism as Zcash Orchard.

#### Taiga balance vs Application balance
Certain applications might allow to create more value having less input, which makes the total value change non-zero. This application-specific balance is different from the Taiga balance and the application needs to make sure the transaction is balanced in the Taiga sense by adding some non-zero value dummy notes to the transaction.

## 6. Instantiations
|Function|Instantiation|Domain/Range|Description|
|-|-|-|-|
|Nullifier PRF|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|$\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = \mathrm{Extract}([PRF_{nk}(ρ) + ψ \mod{q}]K + cm)$|
|`nk` commitment|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|`Com(nk) = Poseidon(nk, user_derived_key)`; used to protect `nk` stored in a note. `user_derived_key` is currently not used
|`PRF_nk`|Blake2s|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|`nk = PRF_nk(nk, r)`| Used to derive `nk`; currently not implemented
|address|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$| `address = Poseidon(app_data_dynamic, nk_com)`; compresses the data fields that contain some ownership information
|`NoteCommit`|[Sincemilla](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html)|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|
|`VPCommit`|Blake2s|-|Efficient over both $\mathrm{F}_p$ and $\mathrm{F}_q$
|`PRF_vb`|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|`value_base = hash_to_curve(Poseidon(desc_app, app_data_static))`; compresses the fields related to the resource type
|`ValueCommit`|Pedersen-like|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|`cv = (v_i * VB_i - v_o * VB_o) + r[R]`, `VB_x` - value base of a note
|VE|DH + Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$| `ek = DH(recv.pk, sender.sk)`, `ce = Poseidon(note, ek)`
|Binding signature|||


## 7. Taiga Execution Model
### Taiga partial transaction

Taiga uses partial transactions to build atomic Taiga transactions. For partial transactions, it is required that all VP proofs are valid but the partial transaction is not balanced. Later, valid partial transactions are composed in a way that the total set of partial transactions balances, which is proven by the binding signature check.
If a partial transaction is balanced, it is transformed into a transaction immediately.

Each Taiga `ptx` contains n input and n output notes. Currently, `n = 2`. Each of the notes requires at least one VP to be satisfied, resulting in at most `2n` VP proofs per `ptx`. The VP is called once per `ptx`, meaning that if the `ptx` has 2 or more notes belonging to the same application, the total amount of non-dummy proofs is reduced.

Note: it is possible that a VP requires checks of other VPs in order to be satisfied. In that case, the total amount of VPs checked could be more than `2n`, but we can count such check as a single check.

#### Partial transaction fields
Each Taiga ptx contains:
- `n` actions (one action covers one input and one output note):
    - `π_action` - proof of the action
    - `(rt, nf, cm, com_vp_input, com_vp_output, ce)` - action's public input
- for each input note:
    - `π_VP` proof
    - VP's public input
    - `desc_VP`
    - `extra_desc_VP` (if the "main" VP requires additional VPs to be checked) 
- for each output note:
    - `π_VP` proof
    - VP public input
    - `desc_VP`
    - `extra_desc_VP` (if the "main" VP requires additional VPs to be checked)

#### Validity of a `ptx`
A partial transaction `ptx` is valid if:
1. For each $i$-th action:
    - [if `is_merkle_checked = true`] `rt_i` is a valid Merkle root from current or past epoch.
    - `Verify(desc_Action, ActionPublicInput, π_action_i) = True`
2. For each VP:
    - `Verify'(desc_VP, VPPublicInput, π_VP) = True`
    
### Taiga transaction
Taiga transaction is build from a set of partial transactions. Unlike partial transactions, a transaction must balance, this is checked by the binding signature.

#### Taiga transaction fields
A Taiga transaction contains:
- a set of `k` partial transactions: `[ptx_1, .., ptx_k]`
- a binding signature

#### Validity of a `tx`
A transaction is valid if:
- each partial transaction in the `tx` is valid
- the binding signature is correct
    
### Taiga state
Taiga is stateless in the sense that it doesn't store and update the state, but Taiga produces the state change that assumes a certain state structure.

For each epoch the state consists of:
- Merkle tree, $CMtree$, of note commitments with root `rt`
    - Supporting add: $CMtree.add(cm, ce)$
    - Only `cm` is hashed in derivation of `rt`, note encryption `ce` is simply stored alongside `cm`
- Set of input note nullifiers, $NF$
    - Supporting add: $NF.add(nf)$
    - Supports memership checks
    
The state should make past `rt` accessible as well.

#### Produced state change
A valid Taiga transaction `tx` induces a state change as follows:
1. For each `nf`: $NF.add(nf)$
1. For each `cm` with associated `ce`: $MT.add(cm, ce)$
    - `rt` is not updated for operation
1. Re-compute `rt` of $MT$
