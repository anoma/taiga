# Taiga Spec Draft

⚠️ Instantiations and the exact formulas are unstable ⚠ ️

## 1. Proving system

We use Halo2/IPA with [Pasta curves](https://github.com/zcash/pasta) developed by Zcash to instantiate our proving system.

### 1.1 Circuits
Let `C(x; w) ⟶ 0/1` be a circuit. As a group, an elliptic curve has arithmetic defined within the _scalar field_ (i.e. the prime number of points of the curve). When we formulate circuits, we use this scalar field. The circuit is represented as polynomials over the chosen curve's scalar field, following [plonk-ish arithmetization](https://zcash.github.io/halo2/concepts/arithmetization.html). When we want to _commit_ to these values in the scalar field, we end up with values in the _base field_. When using these committed values, we encounter what is known as _non-native arithmetic_. This is the motivating factor for proposing a _cycle of curves_. 

### 1.2 Cycle of curves
Cycles of curves serve as a solution to the problem of non-native arithmetic by employing a pair of elliptic curves, each operating in a manner that the base field of one becomes the scalar field of the other.
|Name|Base field| Scalar field|Purpose|Instantiation|
|-|-|-|-|-|
|$E_p$|$\mathbb{F}_p$|$\mathbb{F}_q$|ECC gadget, Accumulation circuit| [Pallas](https://github.com/zcash/pasta#pallasvesta-supporting-evidence)
|$E_q$|$\mathbb{F}_q$|$\mathbb{F}_p$|Action and VP circuits| Vesta|

### 1.3 Proving system interfaces
||Interface|Description|
|-|-|-|
|__Generate Verifier key__|`keygen_vk(C) ⟶ vk`|`C` is turned into a *circuit description* or *verifying key* `vk`, a succinct representation of the circuit that the verifier uses to verify a proof|
|__Generate Proving key__|`keygen_pk(C, vk) ⟶ pk`|Generate a proving key from a verifying key and an instance of circuit|
|__Prove__|`P(C, pk, x, w) ⟶ π`|Prove that a circuit is satisfied given instance `x` and witness `w`|
|__Verify__|`V(vk, x, π) ⟶ 0/1`|Verify the proof|

## 2. Notes
Note is an immutable particle of the application state in the UTXO model.

### 2.1 Note structure
|Variable|Type|Description|
|-|-|-|
|`note_type`|$E_p$|Identifier of the note's application|
|`app_data_dynamic`|$\mathbb{F}_p$|Encoding of the application's extra data|
|`v`|u64|Fungible quantity specific to a note type|
|`cm_nk`|$\mathbb{F}_p$|Commitment to the nullifier key that will be used to derive the note's nullifier|
|`ρ`|$\mathbb{F}_p$|The nullifier `nf` of the consumed note is equal to the `ρ` of the created note from the same Action description (see Orchard). This guarantees the uniqueness of a note|
|`ψ`|$\mathbb{F}_p$|$ψ = PRF^{\psi}(0, rseed, ρ)$|
|`is_merkle_checked`|bool|Checked note flag. It indicates whether the note's commitment Merkle path should be checked when consuming the note.|
|`rcm_note`|$F_q$|A random commitment trapdoor $rcm\_{note} = PRF^{\texttt{rcm_note}}(1, rseed, ρ)$|

Note: the value size cannot be bigger or close to the curve's scalar field size (to avoid overflowing) but besides that there are no strict reasons for choosing `u64`. We can use more notes to express a value that doesn't fit in one note (splitting the value into limbs). Having bigger value size requires fewer notes to express such a value and is more efficient. For example, a value size of 128 bits would require two times less notes to express a maximum value

#### Derivation of random parameters

The note contains two randomness parameters:
- `rcm_note` is used as a commitment randomness
- `ψ` provides additional randomness for the nullifier derivation

Both fields are derived from a parameter `rseed`.
A note is created from a freshly derived `rseed` parameter, but only `rcm_note` and `ψ` go to the note commitment and are verifiably encrypted. The transmitted note is reconstructed from `rcm_note` and `ψ` parameters. Currently circuits don't check if `rcm_note` and `ψ` are derived from `rseed`.

#### Application-related fields

Each note has three fields with application data.

|Variable|Type/size|Description|
|-|-|-|
|`cm_app_vk`|| Contains the application's main VP verifier key. Used to identify the application the note belongs to. As the verifier key itself is large, the notes only store a commitment to it.|
|`app_data_static`||Contains the application data that affects fungibility of the note. Along with `cm_app_vk`, it is used to derive note's type||
|`app_data_dynamic`||Contains the application data that doesn't affect the fungibility of the note|

#### Note type

The type of a note is derived from two application-related fields: `cm_app_vk` and `app_data_static`.

$NT = PRF^{nt}(cm_{\texttt{app\_vk}}, \texttt{app\_data\_static})$

#### Value commitment

Used to ensure balance across the notes in an Action.

Comparison between Orchard and Taiga's value commitment: 
- Orchard: one-type value commitment computation (Orchard spec p. 93, homomorphic pedersen commitment):
$cv = [v^{in} - v^{out}]NT + [rcv]R$
- Taiga: multiple types value commitment computation used in Taiga:
$cv = [v^{in}]NT^{in} - [v^{out}]NT^{out} + [rcv]R$

|Variable|Type/size|Description|
|-|-|-|
|$v^{in}$|${0..2^{64} - 1}$||
|$v^{out}$|${0..2^{64} - 1}$||
|$NT^{in}$|$E_p$|Input note's type|
|$NT^{out}$|$E_p$|Output note's type|
|`R`|$E_p$|Randomness base, fixed|
|`rcv`|$\mathbb{F}_q$|Value commitment trapdoor|
|`cv`|$E_p$||

### 2.3 Note commitment

Note commitments are stored in a global commitment tree. The global commitment tree contains commitments to all of the notes ever existed. Adding a note's commitment to the commitment tree announces the creation of the note. The notes are never removed from the tree. Instead, notes are invalidated by revealing their nullifiers.

|Name|Type/size|Description|
|-|-|-|
|`cm` |$E_p$|$cm = \mathrm{NoteCom}(note, rcm\_{note})$|

### 2.4 Nullifier
Note nullifiers are stored in a global nullifier set. Adding a note's nullifier to the set invalidates the note. We use the same nullifier derivation algorithm as in Orchard: $\mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm) = PRF^{nf}_{nk}(ρ, ψ, cm)$.

|Name|Type/size|Description|
|-|-|-|
|`nf`|$\mathbb F_p$|$nf = \mathrm{DeriveNullifier}_{nk}(ρ, ψ, cm)$
|`nk` | $\mathbb F_p$ | the nullifier deriving key|
|`ρ`| $\mathbb{F}_p$ | the nullifier of an old (consumed) note|
|`ψ`| $\mathbb{F}_p$ | additional nullifier randomness|
|`cm` | $E_p$| note commitment |
|`K`|$E_p$| a fixed base generator of the Pallas curve|
|`Extract` | $(\mathbb F_p$, $\mathbb F_p) \rightarrow \mathbb F_p$ | the $x$ coordinate of a point in $E_p$|
|$PRF^{nf}_{nk}(\rho)$|$\mathrm{F}_p \times \mathrm{F}_p \rightarrow \mathrm{F}_p$||


#### 2.4.1 Nullifier deriving key `nk`

The nullifier key for the note is derived when the note is created and is only known to the note's owner (or anyone the owner reveals the key to). Knowledge of the note's nullifier key is necessary (but not sufficient) to create the note's nullifier and invalidate the note.

⚠️ Not implemented, might be changed

$nk = PRF^{nk}_{r}(\mathrm{PERSONALIZATION\_NK})$.

|Name|Type/size|Description|
|-|-|-|
|`PERSONALIZATION_NK`|constant-size string|`Taiga_PRF_NK`, constant|
|`r`||PRF randomness

### 2.5 Verifiable encryption
Encryption is used for in-band distribution of notes. Encrypted notes are stored on the blockchain, the receiver can scan the blockhcain trying to decrypt the notes and this way to find the notes that were sent to them.

We want the encryption to be verifiable to make sure the receiver of the notes can decrypt them. In other systems like Zcash the sender and the creator of the note are the same actor, and it doesn't make sense for the sender to send a corrupted message to the receiver (essentially burning the note), but in Taiga the notes are often created and sent by different parties.

We use the combination of DH key exchange with symmetric encryption.

$sk = DH(pub_{recv}, priv_{send})$

$ce = Encrypt(note, sk)$

Not all of the note fields require to be encrypted (e.g. note commitment), and the encrypted fields may vary depending on the application. To make sure it is flexible enough, the encryption check is performed in VP circuits.

### 2.6 Unchecked notes and dummy notes
A note is _unchecked_ if it doesn’t need to be inserted in the note commitment tree (i.e. created) before it can be consumed. An unchecked note is marked unchecked by setting the `is_merkle_checked` flag to `false`. For unchecked notes the Merkle authentication path is not checked when consuming the note. An example of an unchecked note is an _intent note_, since both the creation and the consumption of an intent happen within the same transaction.

As in ZCash, a note is _dummy_ if its `value` field is zero and therefore it doesn’t affect the balance of a transaction.

## 3. Circuits
### 3.1 The Action Circuit

The action circuit `ActionCircuit(x; w)` checks that the Taiga rules are being followed by a partial transaction. The Action circuit performs checks over 1 input and 1 output note. A partial transaction containing `n` input and `n` output notes requires `n` Action proofs. The circuit is arithmetized over $\mathbb{F}_p$.

#### Inputs
Public inputs (`x`):
1. `rt` - the root of the commitment Merkle tree
2. `nf` - input note nullifier
3. `cm_vp_in` - input note's application VP commitment
4. `cm` - output note commitment
5. `cm_vp_out` - output note's application VP commitment

Private inputs (`w`):
1. `in_note = (note_type, v, cm_nk, ρ, ψ, is_merkle_checked, rcm_note)` - input note opening
2. `(cm_app_vk, rcm_vp)` - opening of `cm_vp_in`
3. `out_note = (note_type, v, cm_nk, ρ, ψ, is_merkle_checked, rcm_note)` - output note opening
4. `(cm_app_vk, rcm_vp)` - opening of `cm_vp_out`

Note: opening of a parameter is every field used to derive the parameter

#### Checks
- For input note:
    - If `is_merkle_checked = true`, check that the note is a valid note in `rt`: there is a path in Merkle tree with root `rt` to a note commitment `cm` that opens to `note`
    - Nullifier integrity: $nf = DeriveNullifier_{nk}(note)$.
    - Application VP integrity: $cm_{vp} = VPCommit(cm_{app\_vk}, rcm_{vp})$
    - Note type integrity: $nt = PRF(cm_{app\_vk}, \texttt{app\_data\_static})$
- For output note:
    - Commitment integrity(output note only): $cm = NoteCom(note, rcm_{note})$
    - Application VP integrity: $cm_{vp} = VPCommit(cm_{\texttt{app\_vk}}, rcm_{vp})$
    - Value base integrity: $nt = PRF(cm_{app\_vk}, \texttt{app\_data\_static})$
- Value commitment integrity: $cv = ValueCommit(v_{in}, v_{out}, NT_{in}, NT_{out}, rcv)$

Note: unlike MASP, the type in Taiga is not used to compute note's commitment and the Action circuit doesn't take `nt` as private input but computes it from the note fields, and it is checked for both input and output notes.

### 3.2 Validity Predicate (VP) circuits
Validity predicate is a circuit containing the application logic. Validity predicates take `n` input and `n` output notes, are represented as Halo2 circuits `VP(x; w) ⟶ 0/1` and arithmetized over $\mathbb{F}_p$.

#### Inputs
Public inputs (`x`):
- $nf_1, …, nf_n$ - input note nullifiers
- $cm_1, …, cm_n$ - output note commitments
- $ce_1, …, ce_n$ - encrypted output notes
- custom public inputs

Private inputs (`w`):
- $note^{old}_1, …, note^{old}_m$ - input notes openings
- $note^{new}_1, …, note^{new}_n$ - output notes openings
- custom private inputs

Each validity predicate has a fixed number of public inputs and unlimited amount of private inputs. Currently, the allowed number of public inputs is limited to `20`. 

#### Checks
As opening of the notes are private parameters, to make sure that notes that the VP received indeed the ones that correspond to the public parameters, VP must check:

1. Input note nullifier integrity: for each $i ∈ {1, …, m}, nf_i = DeriveNullifier_{nk}(ρ, ψ, cm)$
2. Output note commitment integrity: for each $i ∈ {1, …, n}, cm_i = NoteCommit(note, rcm_{note})$
3. Encrypted note integrity: for each $i ∈ {1, …, n}, ce_i = Encrypt(note, pub_{recv})$

Note: encryption can be customized per application. Some applications might encrypt more fields, others - less. The size of the encrypted note does leak some information

All other constraints enforced by VP circuits are custom.

#### Finding the owned notes
A VP takes all notes from the current `ptx` as input which requires a mechanism to determine which note is the application's note being currently checked. Currently, to determine whether a note belongs to the application or not, Taiga passes the note commitment (for output notes) or the nullifier (for input notes) of the owned note as a tag. The VP identifies the owned note by its tag.

#### VP commitment
In the presence of a VP proof for a certain note, VP commitment is used to make sure the right VP is checked for the note. It makes sure that `vp_vk` the note refers to and `vp_vk` used to validate the VP proof are the same.

VP commitment has a nested structure: `VPCommit(vp, rcm_vp) = Com(cm_vp_vk, rcm_vp)`, where `cm_vp_vk = VKCommit(vp_vk)`.

The check is done in two parts:
1. The Action circuit checks that the VP commitment `cm_vp` is derived with `cm_vp_vk` the note refers to:
`cm_vp = Com(cm_vp_vk, rcm_vp)`
2. The verifier circuit checks that the VP commitment is computed using the `vp_vk` that is used to validate the VP proof:
`cm_vp = Com(VKCommit(vp_vk), rcm_vp)`

As the outer commitment `VPCommit` is verified in both Action and verifier circuit which are arithmetized over different fields, the outer commitment instantiation should be efficient over both fields.

As the inner commitment `VKCommit` is only opened in the verifier circuit, it only needs to be efficient over the pallas curve's scalar field $\mathbb{F}_q$.

## 4. Circuit Accumulation
TBD: Halo2 accumulation

### 5. Binding signature
Binding signature is used to make sure the transaction is balanced. Value commitments produced in each partial transaction are accumulated and checked against the commitment to the expected net value change. The value change might be zero, indicating that the whole transaction was done in the schielded space, or non-zero, indicating that some value came from/to the transparent space. We use the same binding signature mechanism as Zcash Orchard.

#### Taiga balance vs Application balance
Certain applications might allow to create more value from less input value, which makes the total value change non-zero. This application-specific balance is different from the Taiga balance and the application needs to make sure the transaction is balanced in the Taiga sense by adding some non-zero value dummy notes to the transaction.

## 6. Instantiations
|Function|Instantiation|Domain/Range|Description|
|-|-|-|-|
|$PRF^{nf}$|Poseidon|$\mathrm{F}_p \times \mathrm{F}_p \rightarrow \mathrm{F}_p$|$PRF^{nf}_{nk}(ρ) = Poseidon(nk, \rho)$|
|$PRF^{nk}$|Blake2s|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|$PRF^{nk}_{r}(\texttt{PERSONALIZATION\_{NK}}) = Blake2s(\texttt{PERSONALIZATION\_{NK}}, r)$| Used to derive `nk`; currently not implemented
|$PRF^{nt}$|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|$PRF^{nt} = hash\_to\_curve(Poseidon(app\_vk, \texttt{app\_data\_static}))$
|$PRF^{\texttt{rcm\_note}}$|Blake2b|$ \mathrm{F}_p \times \mathrm{F}_p \times \mathrm{F}_p \rightarrow \mathrm{F}_p$|Used to derive note commitment randomness|
|$PRF^{ψ}$|Blake2b|$\mathrm{F}_p \times \mathrm{F}_p \times \mathrm{F}_p \rightarrow \mathrm{F}_p$|Used to derive ψ|
|`NKCommit`|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$|$NKCommit(nk) = Poseidon(nk,\texttt{user\_derived\_key})$; used to protect `nk` stored in a note. `user_derived_key` is currently not used
|`NoteCommit`|[Sincemilla](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html)|$\mathrm{F}_p \rightarrow \mathrm{F}_p \times \mathrm{F}_p$|
|`ValueCommit`|Pedersen with variable type|$\mathrm{F}_p \rightarrow \mathrm{F}_q$|$cv = [v_i] * NT_i - [v_o] * NT_o + [r]R$
|`VPCommit`|Blake2s||Efficient over both $\mathrm{F}_p$ and $\mathrm{F}_q$
|`VKCommit`|-||Efficient over the outer curve's scalar field|
|address|Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$| `address = Poseidon(app_data_dynamic, cm_nk)`; compresses the data fields that contain some ownership information
|`Encrypt`|DH + Poseidon|$\mathrm{F}_p \rightarrow \mathrm{F}_p$| $Encrypt(note, pub_{recv}, priv_{send}) = Poseidon(note, DH(pub_{recv}, priv_{send}))$
|Binding signature|||See Orchard binding signature


## 7. Taiga Execution Model
### Taiga partial transaction

Taiga uses partial transactions to build atomic Taiga transactions. For partial transactions, it is required that all VP proofs are valid but the partial transaction is not balanced i.e. $v^{in} - v^{out} \neq v^{balance}$. Later, valid partial transactions are composed in a way that the total set of partial transactions balances, which is proven by the binding signature check.
If a partial transaction naturally balances, it is transformed into a transaction immediately.

Each Taiga `ptx` contains `n` input and `n` output notes. Currently, `n = 2`. Each of the notes requires at least one VP to be satisfied, resulting in at least `2n` VP proofs per `ptx`.


Note: Right now, each note requires a separate VP proof, even if they belong to the same application. Eventually the VP might be called just once per `ptx`, meaning that if the `ptx` has 2 or more notes belonging to the same application, the total amount of non-dummy proofs is reduced.

Note: it is possible that a VP requires checks of other VPs in order to be satisfied. In that case, the total amount of VPs checked could be more than `2n`, but we can count such check as a single check.

#### Partial transaction fields
Each Taiga ptx contains:
- `n` actions (one action covers one input and one output note):
    - `π_action` - proof of the action
    - `(rt, nf, cm, cm_vp_input, cm_vp_output, ce)` - action's public input
- for the input notes:
    - `π_VP` proof
    - VP's public input
    - `VP_vk`
    - `extra_VP_vk` (if the "main" VP requires additional VPs to be checked)
- for the output notes:
    - `π_VP` proof
    - VP public input
    - `VP_vk`
    - `extra_VP_vk` (if the "main" VP requires additional VPs to be checked)

#### Validity of a `ptx`
A partial transaction `ptx` is valid if:
1. For each $i$-th action:
    - [if `is_merkle_checked = true`] `rt_i` is a valid Merkle root from current or past epoch.
    - `Verify(desc_Action, ActionPublicInput, π_action_i) = True`
2. For each VP:
    - `Verify'(desc_VP, VPPublicInput, π_VP) = True`
    - Public input consistency: VP's public input `nf` and `cm` are the same as in Actions' public input

### Taiga transaction
Taiga transaction is built from a set of partial transactions. Unlike partial transactions, a transaction must balance, which is checked by the binding signature.

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
    - Supports membership checks
 
The state should make past `rt` accessible as well.

#### Produced state change
A valid Taiga transaction `tx` induces a state change as follows:
1. For each `nf`: $NF.add(nf)$
1. For each `cm` with associated `ce`: $MT.add(cm, ce)$
    - `rt` is not updated for operation
1. Re-compute `rt` of $MT$

8. Communication between the shielded and transparent pools
State transitions that do not preserve privacy are called *transparent*. Assuming that the system allows both transparent and shielded state transitions, we say that all of the valid notes created as a result of shielded state transitions form a *shielded pool* and the valid notes created as a result of transparent state transitions form a *transparent pool*. The action of moving data from transparent to shielded pool is called *shielding*, the opposite is called *unshielding*. Shielding (or unshielding) is done by destroying notes in one pool and creating the corresponding notes in the other. *Balancing value* $v^{balance}$ indicates the data move between the pools:

- $v^{balance} = 0$ if the current transaction doesn't move data between pools
- $v^{balance} < 0$ refers to the value moved from the transparent to the shielded pool
- $v^{balance} > 0$ refers to the value moved from the shielded to the transparent pool

The difference between total input value and total output value of a proposed transaction is checked against the balancing value with the help of the binding signature.