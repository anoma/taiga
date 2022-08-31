# THE PBC TODO LIST:

"Experimental" tasks can be done in parallel, however are not necessary for the first iteration of PBC. All other tasks should be (at minimum) attempted for the proof-of-concept/prototype/first iteration.

## Conceptual tasks

1. Define address, note, commitment and signature formats
    - Try to eliminate BLAKE2s from design, particularly from `com_vp`
1. Completely formalize spec
    - Formalize proof system interfaces
        - Preproc, Blind
    - Diagrams
    - Add types/lengths to all spec data fields
    - Write formal descriptions of all in-circuit and out-of-circuit operations / checks
    - Migrate github issue details to either PBC spec, or a gitbook
    - End result should resemble Zcash Orchard protocol spec and/or Halo 2 gitbook, but better (hopefully)!
    hiding

### Pending features

1. Figure out how to input "time" into VPs
    - E.g. subscriptions or trades that are scheduled or cancel automatically
    - Simple approach: public input block number. Problem: may not be included in exactly that block
1. Figure out VP cyclic reference problem. E.g. two VPs that can send to each other.
    - Right now embedding another address in a VP changes the VP's address, so cyclic refs not possible
1. Light client transaction scanning provisions
    - The Zcash light client model sucks, and SGXs also suck / are going away
    - Some prior work e.g. https://eprint.iacr.org/2021/089
    - We need to do more of a research survey and evaluation here
    - Reach out to Penumbra and/or ECC and discuss this together

### Other

1. Interface with engineering/ledger/transparent trade team for design uniformity

## Implementation tasks

1. Proof system choice and interface:
    - Halo 2 first then perhaps ark-plonk / Plonkup.
    - Benchmark different approaches
1. Implement Action circuits:
    - Add multi-asset support
        - ~~Derive new asset_generator using Poseidon~~
        - ~~Change value commitment to use new asset_generator~~
        - Add app_vp input
        - Add asset/app type to note format
        - Add data field/tag to note format for NFTs
        - Make new multi-asset tests for all of these
        - Explore using alternative Zcash multi-asset approach
        - Use app vps for balancing tx instead of homomorphic value commitments
    - Change address format
        - Implement VP commitments in address
        - Add com_vp public input and add a check against the address
        - Let `com_vp` be transparent initially, then add hiding
        - Make tests
    - Implement nullifier key derivation
        - (should be carefully derived to avoid any issues)
        - `nk` should be "random", since it is used as a PRF key.
        - Just let user generate it randomly? Need to investigate further.
        - Derive w/ PRF? We don't have secret keys for all vps.
        - Derive w/ hash? Might be expensive.
    - Implement both as single circuit (Action) and dual-circuit (Spend and Output), evaluate which is better
    - Modify all existing Zcash tests for compatibility
1. Implement VPBlind circuit:
    - Implement addition of blinding factor using native arithmetic (VPBlind circuit over Pallas curve) ✓
    - Implement non-native arithmetic gadget and implement VPBlind circuit over Vesta curve
    - Implement BLAKE2s gadget for `com_vp` (or use ark-plonk, or remove need for BLAKE2s)
    - Make tests
1. Implement example VPs (all features required from example userflows)
    - Implement VP circuit format (including any nonmutable data/parameter)
    - Implement (Zcash style) signature check in VP circuit
        - Option 1: each VP include one external signature check
        - Option 2: everything done "in-circuit"
        - Multi-sig extenstions (such as variants of MuSig)
    - Spending VPs
        - Single signature ✓
        - Multisignature
        - Asset swap
        - Subscription
        - Content based VP
        - Conditional spend/joint funding
        - Trade intent
    - Receive VPs
        - Allow all 
        - Reject all 
        - Whitelist sender ✓
        - Whitelist asset type
    - App VPs
        - Check tx balance
        - Shield/unshield apps
        - Swap: mint/burn new/old apps
    - Experiment: storing mutable VP data/state in a special NFT 
    - All other user workflows (the more examples we implement, the better)
    - Implement verifiable output note encryption
        - Ideally use ElGamal for simplicity
        - Due diligence in exploring Poseidon based verifiable encryption
    - Implement "default" receiving VP logic for short addresses
    - Make tests for all VPs
1. Implement transaction preparation and verification
    - Verify Actions > Verify account VPs > Verify app VPs > Ensure all necessary VPs are called with correct public inputs
    - Design and make tests
1. Implement example/proof-of-concept delegated VP proving 
    - E.g. giving delegated prover viewing keys
    - Write example of delegated prover proving Action+VP from viewing keys
1. Implement benchmarks
    - Microbenchmarks for each operation (prove, verify, signature, etc)
    - Benchmarks for each role (end user, validator, block proposer, matchmaker, etc)
    - Benchmarks for blockchain scanning for shielded tx using new verifiable encryption 
1. VP compilation / interface
    - Compile Juvix to VP circuits (**interface with PLT team on this**)
    - Implement all the example VP circuits in high-level interface
1. Evaluate/implement if personalization changes are necessary
    - Orchard uses personalized constants that are hard-coded
    - decide if we need to change constants for domain separation
1. Code management tasks
    - Manage the Orchard dependency
        - this includes regularly merging from Zcash's main branch so we don't get out of date, and managing all the public visibility changes
        - Reusing as much as possible from the orchard crates, refactoring as needed

## After first iteration

1. Review all tests, benchmarks, features, found bugs, etc
1. Make recommendations for next iteration of PBC
1. Next steps: Implement proof of concept accumulation scheme 
