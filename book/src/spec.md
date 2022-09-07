# Taiga Spec Working Draft

To be edited as design changes. Please make changes as necessary. Keep it **concise** and **precise**.

## Notation

$E_M$ means the main curve under which Action and VP circuits (i.e. user and application validity predicates) are defined.

$E_O$ means the outer curve. $E_I$ means the inner curve.

$\mathbb{F}_q$ stands for the base field of $E_M$. $\mathbb{F}_r$ refers to the scalar field of $E_M$.

### Side note:
- ZCash: 
An action circuit in Orchard is over the Vesta curve. Since an action circuit in Taiga is over $E_M$, we could say that $E_M$ is equivalent to $\mathbb{V}$ in Orchard and $q = r_\mathbb{P}$ = $q_{\mathbb{V}}$, $r = r_\mathbb{V} = q_{\mathbb{P}}$. See 5.4.9.6 Pallas and Vesta in the [ZCash docs](https://github.com/zcash/zips/blob/main/protocol/protocol.pdf).
- Action and vp circuits: arithmetic circuit over $\mathbb{F}_r$.
- VPBlind and Accumulator circuits: arithmetic circuit over $\mathbb{F}_q$.

## Proof system (Plonk / plonkup) interfaces 

Main interfaces: Preprocess, Prove, Verify.

- Polynomial commitment scheme for polynomials, where a commitment $Com$ is a point of an elliptic curve $E$ with scalar field $\mathbb F_r$ and base field $\mathbb{F}_q$, and $d$ is the bounded degree of any polynomial in the scheme.
- A circuit with interface `C(x; w) ⟶ 0/1` is a circuit with upto `n` fan-in 3 (or 4) addition / multiplication / lookup gates over $\mathbb{F}_r$. (Following [plonk-ish arithmetization](https://zcash.github.io/halo2/concepts/arithmetization.html), `C(x; w)` can be turned into polynomials over $\mathbb{F}_r$.)
- __Preprocess__: `preproc(C) ⟶ desc_C`. `C` is turned into a *circuit description* which is a sequence of polynomial commitments. (polynomials are computed over $\mathbb{F}_r$ while commitments are generated over $\mathbb{F}_q$)
    - In `ark-plonk`, `desc_C` corresponds to `vd: VerifierData`.
- __Prove__: `P(C, x, w) ⟶ π` (arithmetized over $\mathbb{F}_r$ and $\mathbb{F}_q$)
- __Verify__: `V(desc_C, x, π) ⟶ 0/1` (arithmetized over $\mathbb{F}_r$ and $\mathbb{F}_q$)
- **Blind** over $\mathbb{F}_q$: `Blind(desc_C; r) ⟶ blinded_desc_C`
    - `Blind(desc_vp, r)`:
        - `desc_vp` is 8 group elements (base field $\mathbb{F}_q$) of the form $([q_M(x)], [q_L(x)], [q_R(x)], [q_O(x)], [q_C(x)], [S_{σ_1}(x)], [S_{σ_2}(x)], [S_{σ_3}(x)])$
        - Blinding randomness is 16 elements from $\mathbb{F}_r$: $r = \{(r_{1, B}, r_{2, B}) \mid B = 1, 2, 3, M, L, R, O, C\}$
        - For each "label" `B ∈ {M, L, R, O, C}`:
            - $[q_B'(x)] = r_{1, B}  [Z_H(x)] + r_{2, B} [x \cdot Z_H(x)] + [q_B(x)]$
            - Rationale given in : [Private trade circuit design](https://hackmd.io/LbvsNZmgSNysROgkjjtTKg)
        - For each `i ∈ {1, 2, 3}`:
            - $[S_{σ_i}'(x)] = r_{1, i} [Z_H(x)] + r_{2, i} [x \cdot Z_H(x)] + [S_{σ_i}(x)]$
        - `blind_desc_vp` is $([q_M'(x)], [q_L'(x)], [q_R'(x)], [q_O'(x)], [q_C'(x)], [S_{σ_1}'(x)], [S_{σ_2}'(x)], [S_{σ3}'(x)])$
    - `BlindProver((C, r), x, w) ⟶ π`
        - To generate proof for a blinded circuit, prover needs to take input the blinding randomness

Halo 2 recursion: another proof system with $q$ and $r$ swapped.

### Potential features:

#### Accumulation (of proofs / verifier circuit)

Definitions from Section 4.1 of [BCMS20](https://eprint.iacr.org/2020/499.pdf), and specializing to their Definition 4.2 for Plonk verifiers.

- __Accumulation Prover__ over $\mathbb{F}_r$ and $\mathbb{F}_q$: `AccP(acc, desc_C, x, π) ⟶ (acc', aπ)` ??
- __Accumulation Verify__ over $\mathbb{F}_q$ ?: `AccV(acc, acc', aπ, desc_C, x, π) ⟶ 0/1` ??
- __Accumulation Decider__ over $\mathbb{F}_q$ ?: `AccD(acc) ⟶ 0/1`

## Abstractions

### Data types
- Input / output of each abstract interface, e.g. `Com, Com_q`, defines a distinct type.
- Each distinct data field defines a type, e.g. `v, data, asset_type`.
- Data types are linked via interface definition and usage as required, e.g. `v` is of the same type as the first input to `Com_v`.
- All data types have **fixed length**.

### Commitments / Hash

We blend commitments / hash into a single abstract interface.

- `Com_q(...) ⟶ com` efficient over $\mathbb{F}_q$
- `Com_r(...) ⟶ com` efficient over $\mathbb{F}_r$
- `Com(...) ⟶ com` efficient over **both** $\mathbb{F}_q$ and $\mathbb{F}_r$

Commitments are binding by default (i.e. can be instantiated with hash). If we want blinding (possibly across differnt commitments), we add `rcm` explicitly.

TODO: Fix the exact instantiations / implementations.

Options:
`Com_q, Com_r`: Pedersen, Sinsemilla, Poseidon, Reinforced Concrete
`Com`: Blake2s, SHA256

### Data related to VP circuits (defined in next section)

#### VP description: `desc_vp = preproc(vp)`:

- a number of polynomial commitments
- determinisitic function of `vp` circuit
- description can be further randomized with `Blind`

##### VP full description: `fulldesc_vp = desc_vp || vp_param`:

TODO: Should we use `fulldesc_vp` in place of `desc_vp`?

#### VP commitments: `com_vp = VPCom(desc_vp)`:

- `VPCom(desc_vp; rcm_com_vp) := Com( Com_q(desc_vp), rcm_com_vp)`


### Note

A note encodes:
* the application type,
* the user (owner) address,
* the value (fungible),
* additional data (non-fungible).
```
note = (user_address, app_address, v, data, ρ, ψ)
cm = NoteCom(note, rcm_note)
```

where:

|Variable/Function|Type||
|-|-|-|
|`app_address`| $\mathbb{F}_r$ | a application type encoding `app_vp`|
|`v`| `u64` ($\mathbb F_r$ element in circuit) | the quantity of fungible value |
|`data`| $\mathbb{F}_r$ |non-fungible value(to be decided?)|
|`ρ`| $\mathbb{F}_r$ | an old nullifier|
|`rcm_note` | $\mathbb{F}_r$| a random commitment trapdoor|
|`ψ`| $\mathbb{F}_r$ | the prf output of `ρ` and `rcm_note`|
| `user_address`| $\mathbb F_r$ | address encoding `nk`, `send_vp`, `recv_vp`|
| `NoteCom` | $[\mathbb F_r] \to \mathbb F_r$ | Poseidon hash with eight input elements|

Dummy notes: A note is dummy iff `v = 0`.

Other options of `NoteCom`:
1. `cm = hash_to_curve(note) + [rcm_note] * H` the same as Sapling or Orchard.
2. `cm = [CRH(note||0)] G + [rcm] H`. Then `cm` is a point of $E_M$.

For us: knowing the opening of `address` to `desc_vp_addr_send` <=> can derive `nf` for the notes owned by `address`

### Nullifier deriving key
The nullifier deriving key is denoted `nk` and is randomly generated (by the user).
```
nk = PRF_random(PERSONALIZATION_NK) mod r
```

where:

|Variable/Function|Type||
|-|-|-|
|`random`| 32 bytes | random value |
| `PERSONALIZATION_NK` | string bytes | set to `"Taiga_PRF_NK"`|
| `PRF` | outputs 64 bytes | Blake2b function |

### Nullifier

The nullifier is derived using:
```
DeriveNullifier = PRF(nk, ρ, ψ, cm)
```

where:

|Variable/Function|Type||
|-|-|-|
|`nk` | $\mathbb F_r$ | the nullifier deriving key |
|`ρ`| $\mathbb{F}_r$ | an old nullifier|
|`ψ`| $\mathbb{F}_r$ | the prf output of `ρ` and `rcm_note`|
|`cm` | $\mathbb F_r$ | a commitment from `NoteCom` |
| `PRF` | $[\mathbb F_r] \to \mathbb F_r$ | Poseidon hash with four input elements|

### Nullifier $-$ designed for other options of `NoteCom` (deprecated)

Use the nullifier derivation as in Orchard:
```
DeriveNullifier_nk(ρ, ψ, cm) = Extract([PRF_nk(ρ) + ψ mod r]K + cm)
```

where:

|Variable/Function|Type||
|-|-|-|
|`nk` | $\mathbb F_r$ | the nullifier deriving key |
|`ρ`| $\mathbb{F}_r$ | an old nullifier|
|`ψ`| $\mathbb{F}_r$ | the prf output of `ρ` and `rcm_note`|
|`cm` | $\mathbb F_r$ | a commitment from `NoteCom` |
|`K`|($\mathbb F_r$, $\mathbb F_r$) | a fixed base generator of the inner curve|
| `PRF` | $[\mathbb F_r] \to \mathbb F_r$ | Poseidon hash with two input elements (`nk` and `ρ`)|
|`Extract` | $\mathbb F_r$ | the $x$ coordinate of a (inner curve) point|


## ZK Circuits

### Validity Predicate (VP) circuits

Arithmetized over $\mathbb{F}_r$. Represented as a Plonk circuit `vp(x; w) ⟶ 0/1`.

- expects `m` notes spent and `n` notes created. `m` and `n` could be different for each vp involved in a Taiga transaction.

Public inputs (`x`):
- vp parameter: `vp_param` 
    - a public parameter to `vp`, i.e. immutable data, so that user can customize a global `vp` for example.
- vp public output: `vp_memo` 
    - a public "output" of vp can encode arbitrary data.
    - e.g. encode `rk` to support Sapling/Orchard-type auth. But if we make this choice, then a signature verfication needs to be done on every `rk`.
- spent note nullifiers, `nf_1, …, nf_m`
- created note commitments, `cm_1, …, cm_n`
- for receiving vp: `ce_1, …, ce_n`

Private inputs (`w`):
- spent notes, `old_note_1, …, old_note_m`
- created notes, `new_note_1, …, new_note_n`

Checks that:
1. Encrypted note integrity: for each `i ∈ {1, …, n}`, `ce_i = NoteEnc(new_note_i)`
2. ...

#### First VPs to implement:
- Accept / Reject all
- ZCash Sapling / Orchard authorization
    - Option 1: Check signature, given as private input, in VP circuit
    - Option 2: VP circuit rerandomize verification key to `rk`, which is encoded in `vp_memo`



### Action Circuit

Arithmetized over $\mathbb{F}_r$. Represented as a Plonk circuit, `ActionCircuit(x; w)`.

Public inputs (`x`):
- Merkle root `rt`
- Spent note nullifier `nf`, which commits to note application type, value, and data
    - User VP commitment: `com_vp_addr_send` (commiting to `desc_vp_addr_send`)
    - Application VP commitment: `com_vp_app`
    - `EnableSpend`
- Output note commitment `cm`
    - User VP commitment: `com_vp_addr_recv` (commiting to `desc_vp_addr_recv`)
    - Application VP commitment: `com_vp_app`
    - `EnableOutput`


Private inputs (`w`):
- opening of spent note
    - `note = (address, app, v, data, rho, psi, rcm)`
    - `com_vp_addr` of spent note:
        - `Com_q(desc_vp_addr_send)`, 
        - `nk`, 
        - `Com_q(desc_vp_addr_recv)`, 
        - `rcm_com_vp_addr`
    - `com_vp_app` of spent note:
        - `Com_q(desc_vp_app)`, 
        - `rcm_com_vp_app` 
- opening of created note
    - `note = (address, app, v, data, rho, psi, rcm)`
    - `com_vp_addr` of output note:
        - `Com_r(Com_q(desc_vp_address_send)||nk)`,
        -  `Com_q(desc_vp_address_recv)`, 
        -  `rcm_com_vp_addr`
    - `com_vp_app` of output note:
        - `Com_q(desc_vp_app)`, 
        - `rcm_com_vp_app`

Action circuit checks:
- For spent note `note = (address, app, v, data, ρ, ψ, rcm_note)`:
    - Note is a valid note in `rt`
        - Same as Orchard, there is a path in Merkle tree with root `rt` to a note commitment `cm` that opens to `note`
    - `address` and `com_vp_addr` opens to the same `desc_vp_addr`
        - Note User integrity: `address = Com_r(Com_r(Com_q(desc_vp_addr_send)||nk) || Com_q(desc_vp_addr_recv))`
        - Address VP integrity for input note: `com_vp_addr = Com(Com_q(desc_vp_addr_send), rcm_com_vp_addr)`
        - Nullifier integrity(input note only): `nf = DeriveNullier_nk(note)`.
    - `app` and `com_vp_app` opens to the same `desc_app_vp`
        - Application (type) integrity: `app = Com_r(Com_q(desc_vp_app))`
        - Application VP integrity: `com_vp_app = Com(Com_q(desc_vp_app), rcm_com_vp_app)`
- For output note `note = (address, app, v, data, ρ, ψ, rcm_note)`:
    - `address` and `com_vp_addr` opens to the same `desc_vp_addr`
        - Note User integrity: `address = Com_r(Com_r(Com_q(desc_vp_addr_send)||nk) || Com_q(desc_vp_addr_recv))`
        - Address VP integrity for output note: `com_vp_addr = Com(Com_q(desc_vp_addr_recv), rcm_com_vp_addr)`
        - Commitment integrity(output note only): `cm = NoteCom(note, rcm_note)`
    - `app` and `com_vp_app` opens to the same `desc_vp_app`
        - Application (type) integrity: `app = Com_r(Com_q(desc_vp_app))`
        - Application VP integrity: `com_vp = Com(Com_q(desc_vp_app), rcm_com_vp_app)`

+ checks of `EnableSpend` and `EnableOutput` flags?

Changes and justifications: 
- No more `asset_generator`, `cv`, `cdata`, as they are already committed to in `nf` and `cm`.

### VPBlind Circuit
Arithmetized over $\mathbb{F}_q$.

Public inputs (`x`):
- `com_vp`
- `blind_desc_vp`

Private inputs (`w`):
- `desc_vp`
- `rcm` commitment randomness for `com_vp`
- `r` blinding randomness

VPBlind checks:
- `com_vp = Com(Com_q(desc_vp), rcm)`
- `blind_desc_vp = Blind(desc_vp, r)`

VPBlind ensures that `blind_desc_vp` matches the VP committed to inside `com_vp` hence making usage of the same vp unlinkable across different invocations. 

## Taiga Application

Taiga is an application, i.e. an account with VP (in the Anoma sense) and state, on the Anoma ledger. Taiga maintains a **state** and needs to process **transactions**.
    
### Taiga State

For each epoch the state consists of:
- Merkle tree, $MT$, of note commitments with root `rt`
    - Supporting add: $MT.add(cm, ce)$
    - Only `cm` is hashed in derivation of `rt`, note encryption `ce` is simply stored alongside `cm`
- Set of spent note nullifiers, $NF$
    - Supporting add: $NF.add(nf)$
    - Supports memership checks
    
The state should make past `rt` accessible as well (TODO: can be simplify this?)

### Taiga Transaction `tx`

A Taiga transaction `tx` contains k actions, upto k spent notes, and upto k created notes:
- Each $i$-th action specfies:
    - `ActionCircuit` proof `π_action_i`
    - public input `(rt_i, nf_i, enableSpend, cm_i, enableOutput)`, resulting in overall list of `NF_tx` and `CM_tx`:
        - If `enableSpend = 1`, then `nf_i` is added to `NF_tx`
        - If `enableOutput = 1`, then `cm_i` is added to `CM_tx` and `tx` also provide `ce_i`, which is added to `CE_tx`
- Suppose $m = |NF_{tx}|$, $n = |CM_{tx}| = |CE_{tx}|$
- `tx` gives a list of 2(m + n) `com_vp` with additional data for each `com_vp`:
    - `blinded_desc_vp`, proof `π_blind` and `π_vp`
    - `vp_param`, `vp_memo`
    - `vp_input_notes` $\subseteq \{1, ..., m\}$
        - refers to some nullifiers `NF_tx[vp_input_notes]`
    - `vp_output_notes` $\subseteq \{1, ..., n\}$
        - refers to some commitments `CM_tx[vp_output_notes]`
        - refers to some encryptions `CE_tx[vp_output_notes]`

#### Validity of `tx`
A transaction `tx` is valid if:
1. For each $i$-th action:
    - `rt_i` is a valid Merkle root from current or past epoch.
    - `Plonk.verify(desc_ActionCircuit, (rt_i, nf_i, enableSpend, cm_i, enableOutput), π_action_i) = True`
    - If `enableSpend = 1`, `nf_i` is not in $NF$.
1. For each vp:
    - `Plonk.verify'(desc_VPBlind, (com_vp, blind_desc_vp), π_blind) = True`
        - `π_blind` is over a different proof system than the other proofs, as $VPBlind$ circuit is arithmetized over $F_p$ instead of $F_q$.
    - `Plonk.verify(blind_desc_vp, (vp_param, vp_memo, NF_tx[vp_input_notes], CM_tx[vp_input_notes], CE_tx[vp_input_notes]), π_vp) = True`
    
**Note** Validity check of `tx` is checked inside an [Anoma VP](https://docs.anoma.network/v0.2.0/explore/design/ledger/vp.html).
    
#### Processing of `tx`
A valid Taiga transaction `tx` induces a state change as follows:
1. For each `nf` ∈ `NF_tx`: $NF.add(nf)$
1. For each `cm` ∈ `CM_tx` with associated `ce`: $MT.add(cm, ce)$
    - `rt` is not updated for operation
1. Re-compute `rt` of $MT$

**NOTE**: Processing of `tx` is done inside `code` of an [Anoma transaction](https://docs.anoma.network/v0.2.0/explore/design/ledger/tx.html) with `tx` being `Transaction.data`.


## Accumulator circuits

Why? We can verify a collection of Action and VP proofs efficiently for all proofs in a tx or in a block. Avoids needing to store proofs or `desc_vp` on chain, which are expensive (3.5-5 kB each)

### Decomposition of Plonk verifier

Verification `Verify(desc, x, π)` requires both $F_p$ and $F_q$ arithmetics are needed. To make recursive proof verification more efficient, we can decompose the verifer computation into $F_p$ part and $F_q$ part.

Specifically, we need to construct two circuits `V_q(desc_C, x, π, intval), V_p(intval)`, efficient over $\mathbb{F}_r$ and $\mathbb{F}_q$ respectively, such that `V(desc_C, x, π) = 1` iff `V_q(desc_C, x, π, intval) = 1` and `V_p(intval) = 1`. Note that `V_p` only take input the intermediate value.

`intval` consists of ?? (TODO: pin-down the exact intermediate value):

- Plonk challenges
    - $\beta, \gamma, \alpha, \mathfrak{z}, v,u$ 
- Plonk intermediate values
    - $r_0$
    - $\bar{a}\bar{b}$
    - $(\bar{a} + \beta \mathfrak{z} + \gamma)(\bar{b} + \beta k_1 \mathfrak{z} +\gamma)(\bar{c} + \beta k_2 \mathfrak{z} +\gamma)\alpha + L_1(\mathfrak{z})\alpha^2 + u$
    - $(\bar{a} + \beta\bar{s}_{\sigma 1} + \gamma)(\bar{b} + \beta \bar{s}_{\sigma 2} + \gamma)\alpha \beta \bar{z}_\omega$
    - $Z_H (\mathfrak{z})$
    - $\mathfrak{z}^n$
    - $\mathfrak{z}^{2n}$
    - $v^2, v^3, v^4, v^5$
    - $u \mathfrak{z} \omega$

### Transaction w/ recursive proof

A (recursive) Taiga transaction `tx` contains k actions, upto k spent notes, and upto k created notes:
- Each $i$-th action specfies:
    - public input `(rt_i, nf_i, enableSpend, cm_i, enableOutput)`, resulting in overall list of `NF_tx` and `CM_tx`:
        - If `enableSpend = 1`, then `nf_i` is added to `NF_tx`
        - If `enableOutput = 1`, then `cm_i` is added to `CM_tx` and `tx` also provide `ce_i`, which is added to `CE_tx`
- Suppose $m = |NF_{tx}|$, $n = |CM_{tx}| = |CE_{tx}|$
- `tx` gives a list of 2(m + n) `com_vp` with additional data for each `com_vp`:
    - `vp_param`, `vp_memo`
    
### TxValidity circuits

Circuit $TxValidity_q$

Public input:

- `tx` as specified above
- For each `com_vp`:
    - Intermediate value `intval_vp`
- For each action `action`:
    - Intermediate value `intval_action`
    
Private inputs:

- For each `com_vp`:
    - opening `desc_vp` and randomness `rcm`
    - proof `π_vp`
    - `vp_input_notes` $\subseteq \{1, ..., m\}$
        - refers to some nullifiers `NF_tx[vp_input_notes]`
    - `vp_output_notes` $\subseteq \{1, ..., n\}$
        - refers to some commitments `CM_tx[vp_output_notes]`
        - refers to some encryptions `CE_tx[vp_output_notes]`
- For each `action`:
    - proof `π_action`

Cicuit checks that:

- For each `com_vp`:
    - `desc_vp` is a valid opening, i.e. `com_vp = VPCom(desc_vp, rcm)`
    - `V_q(desc_vp, (vp_param, vp_memo, NF_tx[vp_input_notes], CM_tx[vp_input_notes], CE_tx[vp_input_notes]), intval_vp, π) = 1`
- For each `action`:
    - `V_q(desc_ActionCircuit, action, π_action, intval_action) = 1`
    
Additional checks outside of $TxValidity_p$:
- `V_q(intval) = 1` for all `intval` for vp and action
- Each `rt_i` is a valid Merkle root for current or previous epoch
- No `nf_i` are spent
    
### Accumulator circuit

<!--
Arithmetized over F_p
Represented as two Plonk circuits, $AccumulatorCircuit_1(x; w)$ and $AccumulatorCircuit_2(x; w)$.

The reason it is two circuits is because the Plonk Verifier includes both F_p and F_q operations. These steps can be separated into one circuit over F_p and one circuit over F_q. Together the two circuits collectively implement the entire Plonk verifier, minus the final check.

$AccumulatorCircuit_1$
Public inputs (`x`):
- list of 2(m + n) `com_vp`
- Action and VP public inputs
    - spent note nullifiers, `nf_1, ..., nf_m`
    - created note commitments, `cm_1, ..., cm_n`
    - created note encryptions, `ce_1, ..., ce_n`
- For each proof being accumulated:
    - Plonk challenges
        - $\beta, \gamma, \alpha, \mathfrak{z}, v,u$ 
    - Plonk proof scalars
        - $\bar{a}, \bar{b}, \bar{c}, \bar{s}_{\sigma1}, \bar{s}_{\sigma2}, \bar{z}_{\omega}$
Private inputs (`w`):
- `desc_VP` for each `com_vp`
- `pi` for each proof accumulated

Checks:
- $\beta, \gamma, \alpha, \zeta, v, u$ = hash of transcripts (step 4 of Plonk paper)
-->

Arithmetized over F_q
$AccumulatorCircuit$
Public inputs (`x`):
- list of 2(m + n) `com_vp`
- For each proof being accumulated:
    - Plonk challenges
        - $\beta, \gamma, \alpha, \mathfrak{z}, v,u$ 
    - Plonk proof scalars
        - $\bar{a}, \bar{b}, \bar{c}, \bar{s}_{\sigma1}, \bar{s}_{\sigma2}, \bar{z}_{\omega}$
    - Plonk intermediate values
        - $r_0$
        - $\bar{a}\bar{b}$
        - $(\bar{a} + \beta \mathfrak{z} + \gamma)(\bar{b} + \beta k_1 \mathfrak{z} +\gamma)(\bar{c} + \beta k_2 \mathfrak{z} +\gamma)\alpha + L_1(\mathfrak{z})\alpha^2 + u$
        - $(\bar{a} + \beta\bar{s}_{\sigma 1} + \gamma)(\bar{b} + \beta \bar{s}_{\sigma 2} + \gamma)\alpha \beta \bar{z}_\omega$
        - $Z_H (\mathfrak{z})$
        - $\mathfrak{z}^n$
        - $\mathfrak{z}^{2n}$
        - $v^2, v^3, v^4, v^5$
        - $u \mathfrak{z} \omega$
- `acc`, input accumulator
- `acc'`, output accumulator
Private inputs (`w`):
- `desc_VP`, `rcm` for each `com_vp`
- proof `pi_vp` for each `com_vp`
- proof `pi_action` for each `Action`

Accumulator circuit checks:
- For each `com_vp`:
    - VP integrity: `com_vp = Com(Com_q(desc_VP), rcm)`
    - Hash integrity: $\beta, \gamma, \alpha, \mathfrak{z}, v,u$ are Poseidon hash of transcript
    - Proof integrity: steps 9-11 of Plonk paper
    - Accumulator integrity
        - Commitment opening is added to `acc'`

Notes:
- Plonk challenges $\beta, \gamma, \alpha, \mathfrak{z}, v,u \in \mathbb{F}_r$ are computed using the Poseidon hash over $\mathbb{F}_r$. 
- Plonk challenges are rounded down to $\mathbb{F}_q$ out of circuit, and Plonk intermediate values are computed in $\mathbb{F}_q$ and cast back to $\mathbb{F}_r$ for input to AccumulatorCircuit
- Intermediate values can be computed from the first 12 scalars - don't need to be stored on-chain
- Net cost per Action/VP proof: 12 scalars = 384 bytes
- Plus Accumulator circuit proof size (3-5 kB)
- Avoids need for Accumulator circuit over F_p

TODO:
- does this actually work?
- *really*?
- Maybe we want a more efficient way to avoid these 12 scalars per accumulated proof 

<!--    - Blinding integrity: - blinded $\bar{a}, \bar{b}, \bar{c}, \bar{s}_{\sigma1}, \bar{s}_{\sigma2}, \bar{z}_{\omega}$ computed 
- Seems like $r_0$ might leak information about `desc_vp`
- scalars $\bar{a}, \bar{b}, \bar{c}$ from `desc_vp` are needed in both accumulator circuits. `Com_q(desc_vp)` only openable in one. Further investigation needed.-->

## Taiga transaction with accumulation
Collections of actions and one big accumulator proof.

A Taiga transaction consist of:
- list of 2(m + n) `com_vp`
- spent note nullifiers, `nf_1, ..., nf_m`
- created note commitments, `cm_1, ..., cm_n`
- created note encryptions, `ce_1, ..., ce_n`
- $\beta, \gamma, \alpha, \mathfrak{z}, v,u, \bar{a}, \bar{b}, \bar{c}, \bar{s}_{\sigma1}, \bar{s}_{\sigma2}, \bar{z}_{\omega}$ for each accumulated proof
- an $AccumulatorCircuit$ proof `pi`
