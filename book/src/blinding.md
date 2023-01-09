# Blinding

In order to verify a proof, we derive a verifier key from a circuit that is later used to verify a proof. 

To check a proof, we need to check it against a verifying key we derive from the circuit. Whoever has a verifier key can verify the proof. However, the verifier key leaks some information about the circuit and hence the circuit itself. So we blind it.

Blinding is a mechanism that helps to keep the circuits secret. Randomizing a circuit without changing its actual properties allows to hide the actual content of the circuit and break the link between two executions of the same circuit. However, instead of randomizing the circuit itself, we randomize the **verifying key** derived from it. A verifier key is derived from a circuit and is used to verify proofs. Blinding verifying keys allows us to achieve the circuit privacy. 

Moreover, the verifier keys are computed from the circuits and are visible by all the verifiers of the proof. These verifier keys are private information that leak privacy and need to be protected.
![img_1.png](img/blinding_img_1.png)

In order to get full privacy, we blind (or randomize) the verifier keys so that a proof can be checked against a verifier key or its blinded (randomized) version.

![img_2.png](img/blinding_img_2.png)

This way, a verifier does not require the private verifier key to check the proof and can check the proof against the blinded vk. Though, this verifier needs a proof that the blinded verifier key they were given comes from the actual verifier key.

![img_3.png](img/blinding_img_3.png)

The blinding technique is used to protect `send_VK`, `recv_VK`, and `app_VK`.
This blinding is done for user's `send_VK` and `recv_VK` as well as for `app_VK`.
