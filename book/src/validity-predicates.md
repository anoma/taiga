# Validity predicate (VP)

In Taiga, there are two types of mechanisms checking validity of a transaction: 
* the first type is the Taiga rules that are the same for all transactions.
* the second type is different for each application and is called **validity predicates**. 


A **validity predicate** is a piece of code defined by an application that authorizes transactions the application is involved in.  A valid (can be published on the blockchain) transaction satisfy the VPs of all involved applications.

A single transaction that changes the state of two applications has to be:
* checked against the Taiga rules
* checked against the VP of the first application
* checked against the VP of the second application

Every VP is called **once** per transaction to validate the state transition (e.g. if two notes of the same app exist, the `appVP` is called only once and is checking the state transitions for both notes at once).
#### Examples
- white list VP allows only specific users to change the application state
- lower bound VP restricts the smallest amount of asset that can be received

Validity predicates exist in both transparent and shielded Anoma (Taiga). Unlike transparent Anoma  VPs that are represented as WASM code and publicly visible, Taiga VPs are arithmetic circuits hidden under ZKP. 
To make sure that the state transition is allowed, VPs in Taiga take the current state (expressed by the spent notes) and the next proposed state (expressed by the output notes) as input and perform the required checks.

## Hierarchical VP structure

Validity predicates in Taiga have a hierarchical structure. For all applications involved in a transaction, their `ApplicationVP` must be checked. These VPs might require validity of some other VPs in order for a transaction to be considered valid. In that case, those other VPs must be checked too.

#### Example of a sub VP
Token applications might have `userVP` for each user where they can define on which conditions they want to transact with other users. In this case `applicationVP` would require the validity of userVPs of all users involved in a transaction.

### Validity predicates as arithemtic circuits

To prove that VPs are satisfied without revealing their content, ZKPs are used. Each transaction has VP proofs of involved parties attached to it, and whoever has the verifier key (VK), can verify the proofs.

![img.png](img/vp_img.png)

#### PLONKish circuits for VPs

Taiga uses a PLONK-based ZKP system (Halo2/ZK-Garage Plonk), and validity predicates are represented as [PLONKish circuits](https://zcash.github.io/halo2/concepts/arithmetization.html). For privacy reasons, all Taiga VPs share the same PLONK configuration (the set of "gates" available), and different VPs are created by specifying the *selectors*.

The VP configuration includes the following "gates" in the PLONK configuration:

* Field addition/multiplication
* Elliptic curve addition and scalar multiplication
* Poseidon hash
  
TODO: update the gate info


### VP interface

For privacy and efficiency, all VPs share the same *public input interface*, but are allowed to have different *private* inputs.

#### Public Inputs

* $\{nf_i\}$ - the set of revealed nullifiers in the transaction
* $\{cm_i\}$ - the set of new note commitments created in the transaction
* $e$ - the current Taiga epoch (used for time-tracking)

TODO: This might include a public key as well

TODO: clarify

#### Private inputs

While not formally required, most validity predicates will have all spent and output notes as private input and will verify that they match public input.
