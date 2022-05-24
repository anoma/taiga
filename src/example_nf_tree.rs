#[test]
fn test_mktree() {
    use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

    use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
    use ark_ff::UniformRand;
    use ark_pallas::PallasParameters;
    use ark_serialize::CanonicalSerialize;
    use rand::thread_rng;

    let mut rng = thread_rng();

    let nb = 6;

    // nullifiers are points of the InnerCurve (Pallas here)
    let nullifiers = (0..nb).map(|_| TEGroupAffine::<PallasParameters>::rand(&mut rng));

    // Leaves of the merkle tree are hashes of the nullifiers (converted into bytes first)
    let leaves: Vec<[u8; 32]> = nullifiers
        .map(|nf| {
            let mut bytes_nullifier = vec![];
            nf.serialize_unchecked(&mut bytes_nullifier).unwrap();
            Sha256::hash(bytes_nullifier.as_slice())
        })
        .collect();

    // Merkle tree
    let mut merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);

    // Proofs
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..=4).ok_or("can't get leaves to prove").unwrap();
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree
        .root()
        .ok_or("couldn't get the merkle root")
        .unwrap();

    assert!(merkle_proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len()
    ));

    // Adding a new nullifier
    let new_nullifier = TEGroupAffine::<PallasParameters>::rand(&mut rng);
    let mut bytes_nullifier = vec![];
    new_nullifier
        .serialize_unchecked(&mut bytes_nullifier)
        .unwrap();
    let hash = Sha256::hash(bytes_nullifier.as_slice());
    merkle_tree.insert(hash);
    merkle_tree.commit();

    // creating a new proof for this new leaf
    let new_merkle_proof = merkle_tree.proof(&[6]);
    let new_merkle_root = merkle_tree
        .root()
        .ok_or("couldn't get the merkle root")
        .unwrap();

    assert!(new_merkle_proof.verify(new_merkle_root, &[6], &[hash], leaves.len() + 1));
}
