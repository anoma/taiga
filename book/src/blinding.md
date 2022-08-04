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
