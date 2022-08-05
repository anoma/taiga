/*
This file contains parts of the spec that is not useful in our current implementation, but is worth to save somewhere.
*/


// about accumulation in the spec

    Halo 2 recursion: another proof system with $q$ and $r$ swapped.

    ### Potential features:

    #### Accumulation (of proofs / verifier circuit)

    Definitions from Section 4.1 of [BCMS20](https://eprint.iacr.org/2020/499.pdf), and specializing to their Definition 4.2 for Plonk verifiers.

    - __Accumulation Prover__ over $\mathbb{F}_r$ and $\mathbb{F}_q$: `AccP(acc, desc_C, x, π) ⟶ (acc', aπ)` ??
    - __Accumulation Verify__ over $\mathbb{F}_q$ ?: `AccV(acc, acc', aπ, desc_C, x, π) ⟶ 0/1` ??
    - __Accumulation Decider__ over $\mathbb{F}_q$ ?: `AccD(acc) ⟶ 0/1`


// about changing the hash function choice in the spec

    TODO: Fix the exact instantiations / implementations.

    Options:
    `Com_q, Com_r`: Pedersen, Sinsemilla, Poseidon, Reinforced Concrete
    `Com`: Blake2s, SHA256

// about another option for nullifier derivation

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

// About accumulation/recursive proof

    ## Accumulator circuits

    Why? We can verify a collection of Action and VP proofs efficiently for all proofs in a tx or in a block. Avoids needing to store proofs or `desc_vp` on chain, which are expensive (3.5-5 kB each)


    ### Transaction w/ recursive proof

    A (recursive) Taiga transaction `tx` contains k actions, upto k spent notes, and upto k created notes:
    - Each $i$-th action specfies:
        - public input `(rt_i, nf_i, enableSpend, cm_i, enableOutput)`, resulting in overall list of `NF_tx` and `CM_tx`:
            - If `enableSpend = 1`, then `nf_i` is added to `NF_tx`
            - If `enableOutput = 1`, then `cm_i` is added to `CM_tx` and `tx` also provide `ce_i`, which is added to `CE_tx`
    - Suppose $m = |NF_{tx}|$, $n = |CM_{tx}| = |CE_{tx}|$
    - `tx` gives a list of 2(m + n) `com_vp` with additional data for each `com_vp`:
        - `vp_param`, `vp_memo`
        
// Still accumulation and transaction


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
