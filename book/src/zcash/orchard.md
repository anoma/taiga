# Orchard
## The Orchard Transaction
![](https://i.imgur.com/1esKr5U.jpg)

## Relationship between the Orchard parameters
![](https://i.imgur.com/jDpXzQr.png)


## Notes

||Sapling |Orchard|
|-|-|-|
|rcm/rseed|<li>$rcm$ is generated randomly[^prec]</li><li>$rseed = rcm$</li>|<li> $rseed$ is generated randomly</li><li><span style="background-color:#ddffcc">$rcm = PRF_{rseed}(5, \rho)$</span></li>|
|note plaintext[^np]|$(leadByte, d, v, memo)$[^prec]|$(leadByte, d,v,$<span style="background-color:#ddffcc">$rseed,$</span>$memo)$[^can]||
|note|$(d, pk_d, v, rcm)$|$(d, pk_d, v,$ <span style="background-color:#ddffcc">$\rho, \psi$</span>$, rcm)$|
|$\rho$|computed only for *positioned notes*, i.e. notes that have a position in the commitment tree, $\rho = H(cm, pos)$|can be computed for any notes: $\rho = nf^{old}$ from the same Action description (or $\rho = []$ if no spent notes in the Action description)|
|note commitment|$cm = Commit_{rcm}(g_d, pk_d, v)$ |$cm = Commit_{rcm}(g_d, pk_d, v,$<span style="background-color:#ddffcc">$\rho, \psi)$</span>|
|derive $nf$|$nf = PRF_{nk}(\rho)$<li>$\rho$</li><li>recipient's $nk$</li>|$nf = [PRF_{nk}(\rho) + \psi]*K + cm, K$ is a point on the Pallas curve<li>$\rho,$</li><li><span style="background-color:#ddffcc">$\psi = PRF_{rseed}(9, \rho),$</span></li><li><span style="background-color:#ddffcc">$cm,$</span></li><li> recipient's $nk$</li> |
|spend|<li>disclose nf</li><li>ZKP of $\rho, ak,$ <span style="background-color:#ffcccc">$nsk$</span></li><li> spend auth signature (PoK of $ask$)</li>|<li>disclose nf</li><li>ZKP of $\rho, ak,$<span style="background-color:#ddffcc">$nk$</span></li><li> spend auth signature (PoK of $ask$)</li>|
|$leadByte$|0x01[^prec] or 0x02[^can]| 0x02|

## Curves
||Sapling|Orchard|
|-|-|-|
|Application circuit EC (key agreement, signatures, etc)|Jubjub|Pallas|
|Proof system EC|BLS12-381|Vesta|
|RedDSA (SpendAuthSig, BindingSig)|RedJubjub|RedPallas|

## Misc
||Sapling|Orchard|
|-|-|-|
|Circuit|Spend/Output|Action: to allow a specific action, set the corresponding flag (enableSpends, enableOutputs)|
|MerkleCRH|PedersenHash|SinsemillaHash|
|NoteCommit[^cv]|PedersenCommit|SinsemillaCommit|
|Derive $ivk$|Blake2s|SinsemillaShortCommit|
|$PRF_{nk}(\rho)$ (used to compute nullifiers)|Blake2s|PoseidonHash|
|PRP (used to generate diversifiers)|-|FF1-AES256|
|Proving system|Groth16|Halo 2|
|Address encoding|Bech32|Bech32m|

## Keys (see [Sapling keys](https://hackmd.io/@yulia/saplingkeys))

|id|name|full name|type|lifetime|description|
|-|-|-|-|-|-|
|1.|sk|spending key|scalar|address|<li>A private key associated with a shielded address</li><li>Authorizes spending of a note</li><li>Generated randomly</li><li>Used to generate other keys &rarr; enough to perform any action</li>|

### Nullifier

|id|name|full name|type|lifetime|description|
|-|-|-|-|-|-|
|2.|~~nsk~~|~~nullifier private key~~|~~scalar~~|-|<span style="background-color:#ffcccc">Doesn't exist in Orchard</span>|
|3.|nk|nullifier deriving key|<span style="background-color:#ddffcc">scalar</span>|address|<li><span style="background-color:#ddffcc">$nk = PRF_{sk}(7)$</span></li><li>Used to derive note nullifiers: <span style="background-color:#ddffcc">$nf = [PRF_{nk}(\rho) + \psi]*K+ cm,$ $K$ is a point on the Pallas curve</span></li> |

### Spend authorization signature

|id|name|full name|type|lifetime|description|
|-|-|-|-|-|-|
|4.|ask|spend authorizing key|scalar|address|<li> Used to derive $ak$, $rsk$</li><li> <span style="background-color:#ddffcc">$ask = PRF_{sk}(6)$</span></li>|
|5.|ak|spend validating key|point|address|<li> $ak = [ask]*P_{\mathbb{G}}, P_{\mathbb{G}}$ is a subgroup generator</li><li>Used to derive $dk, ovk, ivk$ </li><li> Private input to the Action proof: check that $rk$ is a randomization of $ak$ (*spend authority* condition)</li>|
|6.|rsk|-|scalar|transaction|<li>Used to sign the hash of a transaction (proof of spend authority)</li><li> Randomization of $ask$, $rsk = ask + \alpha$, $\alpha$ is a randomness</li>|
|7.|rk|validating key|point|transaction|<li>Used to validate SpendAuthSig</li><li> $rk = [rsk]*P_G = [ask + \alpha]*P_G = ak + \alpha*P_\mathbb{G}$, $P_\mathbb{G}$ is a group generator</li><li>Public input to the Action proof</li>|

### Binding signature

|id|name|full name|type|lifetime|description|
|-|-|-|-|-|-|
|8.|bsk|binding signing key|scalar|transaction|<li>Used to sign the transaction hash</li><li>Computed from value commitment randomnesses $rcv_i$</li>|
|9.|bvk|binding validating key|point|transaction|<li>Used to validate the BindingSig</li><li>Not encoded in the transaction explicitly, must be recalculated</li><li>Computed from value commitments $cv_i$</li><li>$bvk = [bsk]*R$, $R$ is a generator (it is not how the key is computed in practice, but the relationship should be checked by the signer)</li><li>$bvk = ValueCommit_{bsk}(0)$</li>

### Encryption

|id|name|full name|type|lifetime|description|
|-|-|-|-|-|-|
|<span style="background-color:#ddffcc">10.</span>|<span style="background-color:#ddffcc">rivk</span>|<span style="background-color:#ddffcc">ivk commitment randomness</span>|<span style="background-color:#ddffcc">scalar</span>|<span style="background-color:#ddffcc">address</span>|<li><span style="background-color:#ddffcc">$rivk = PRF_{sk}(8)$</span></li><li><span style="background-color:#ddffcc">Used to derive dk and ovk</li><li><span style="background-color:#ddffcc">Used as a randomness in ivk computation</span></li></span>|
|11.|ivk|-|<span style="background-color:#ddffcc">point</span>|address|<li>Used to derive a diversified key $pk_d$</li><li> <span style="background-color:#ddffcc">$ivk = Commit_{rivk}(ak, nk)$</span></li>|
|12.|ovk|outgoing viewing key|scalar|address|<li>Encryption/decryption of outgoing notes</li><li><span style="background-color:#ddffcc">$ovk = PRF_{rivk}(ak, nk)[-l_{ovk}/8:]$</span>[^pyth2]</li>|
|13.|<span style="background-color:#ddffcc">dk</span>|<span style="background-color:#ddffcc">diversifier key</span>|<span style="background-color:#ddffcc">scalar</span>|<span style="background-color:#ddffcc">address</span>|<li><span style="background-color:#ddffcc">$dk = PRF_{rivk}(ak, nk)[:l_{dk}/8]$</span>[^pyth]</li><li><span style="background-color:#ddffcc">Used to derive diversified address ($d, pk_d$)</span></li>|
|14.|$pk_d$|diversified transmission key|point|note<|<li>Used to derive a note encryption key</li><li>Is a part of a diversified (shielded) payment address $(d, pk_d)$</li> <li>$pk_d = [ivk] * g_d = [ivk]* H(d),$<span style="background-color:#ddffcc">$d = PRP_{dk}(idx)$ </span></li> <li>The diversified payment address derived from $idx = 0$ is called the *default diversified payment address*</li>|
|15.|esk|ephemeral secret key|scalar|note|<li><span style="background-color:#ddffcc">$esk = PRF_{rseed}(4)$ </span></li><li> Used to derive $K_{enc}$</li>|
|16.|epk|ephemeral public key|point|note|<li>$epk = [esk]*g_d$[^enc]</li><li> Used to derive $K_{enc}$</li>|
|17.|ock|outgoing cipher key|scalar|note|<li>Symmetric encryption key used to encrypt $C_{enc}$($pk_d$ and $esk$)[^ock]</li><li> $ock = PRF_{ovk}(cv, cm, epk)$</li>|
|18.|$K_{enc}$|-|scalar|note|<li>Symmetric encryption key used to encrypt $np$</li><li>$K_{enc}= KDF([esk]*pk_d, epk)$</li>|
|19.|(nk, ivk)|receiving key|-|address|Allows scanning of the blockchain for incoming notes and decrypt them|
|20.|fvk <span style="background-color:#ddffcc">(ak, nk, rivk)</span>|full viewing key |-|address|<li>Enough to both encrypt & decrypt notes (to derive the corresponding keys), but not enough to spend a note</li><li>Can be used to derive incoming viewing key, outgoing viewing key, and a set of diversified addresses</li>|
|21.|(dk, ivk)|incoming viewing key|-|address|<li>Can be used to decrypt a note</li><li><span style="background-color:#ddffcc">$dk$ is required because it is used to compute $g_d$ ($pk_d$ is a part the decryption output)</li></span>|

#### Encrypt($np$, $pk_d$, $ovk$):
1. Generate $esk$
2. $epk = [esk]*g_d$
3. $K_{enc} = KDF([esk]*pk_d, epk)$
4. $C_{enc} = E_{K_{enc}}(np)$
5. $ock = PRF_{ovk}(cv, cm, epk)$
6. $C_{out} = E_{ock}(pk_d || esk)$ (if $ovk$ is `None`, $ovk$ is generated randomly, $C_{out}$ is garbage encrypted on garbage &rarr; not used for decryption)

&rarr; $ct = (epk, C_{enc}, C_{out})$

#### Decrypt
If the user has $ivk$, they decrypt the note directly deriving $K_{enc}$ from $ivk$:
1. $K_{enc} = KDF([ivk]*epk, epk)$ [^enc]
2. $np = D_{K_{enc}}(C_{enc})$
3. $pk_d = [ivk]*g_d$

If a user has the **full viewing key** (though we only use the $ovk$ component of it), they use it to decrypt the keys $C_{out}$ and then use the decrypted keys to decrypt the note
1. $ock = PRF_{ovk}(cv, cm, epk)$ ($cv$ and $cm$ are parts of the Output description)
2. $pk_d, esk = D_{ock}(C_{out})$
3. $K_{enc} = KDF([esk]*pk_d, epk)$
4. $np = D_{K_{enc}}(C_{enc})$

### Misc

|id|name|full name|type|description|
|-|-|-|-|-|
|22.|(ask, nsk, ovk)|expanded spending key|-|Enough to spend a note|
|23.|$(ask, nsk, ovk, pk_d, c)$|extended spending key|-|ZIP-32|
|24.|(ak, nsk)|proof authorizing key|-|As a part of the spending action, one has to prove the knowledge of $(\rho, ak, nsk)$ and disclose the nullifier|

![](https://i.imgur.com/z1OthzW.png)

[^prec]: Pre-Canopy
[^can]: Canopy onward
[^cv]: ValueCommit uses PedersenHash in both Sapling and Orchard
[^np]: The data needed to spend a note
[^pyth]: first $l_{dk}/8$ bytes (python slice style)
[^pyth2]: last $l_{ovk}/8$ bytes (python slice style)
[^enc]: $[esk] * pk_d = [esk] * [ivk] * g_d = [ivk] * epk$
[^ock]: If the receiver doesn't have $ivk$, they use $ovk$ to decrypt the keys used to encrypt the note plaintext, and then decrypts the note plaintext. If the receiver has $ivk$, they can decrypt the note plaintext directly
