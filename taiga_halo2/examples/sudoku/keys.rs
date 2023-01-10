use halo2_proofs::plonk::{self, Circuit};
use pasta_curves::{pallas, vesta};
use std::{hash::{Hash, Hasher}, io};

#[derive(Debug)]
pub struct VerifyingKey {
    pub(crate) params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub(crate) vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn build<C: Circuit<pallas::Base>>(circuit: &C, k: u32) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(k);

        let vk = plonk::keygen_vk(&params, circuit).unwrap();

        VerifyingKey { params, vk }
    }
}

impl Hash for VerifyingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let s = format!("{:?}", self.vk.pinned());
        s.hash(state);
        let mut v = Vec::new();
        self.params.write(&mut v); // TODO: properly process result
        v.hash(state);
    }
}

#[derive(Debug)]
pub struct ProvingKey {
    pub params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pub pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build<C: Circuit<pallas::Base>>(circuit: &C, k: u32) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(k);

        let vk = plonk::keygen_vk(&params, circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, circuit).unwrap();

        ProvingKey { params, pk }
    }
}

#[test]
fn test_vk_hashing() {
    use std::{io::{stdout, Write}, collections::hash_map::DefaultHasher, time::Instant};
    use rand::rngs::OsRng;
    use taiga_halo2::circuit::vp_examples::TrivialValidityPredicateCircuit;
    use crate::app::valid_sudoku::circuit::SudokuCircuit;

    let sudoku1 = [
        [7, 6, 9, 5, 3, 8, 1, 2, 4],
        [2, 4, 3, 7, 1, 9, 6, 5, 8],
        [8, 5, 1, 4, 6, 2, 9, 7, 3],
        [4, 8, 6, 9, 7, 5, 3, 1, 2],
        [5, 3, 7, 6, 2, 1, 4, 8, 9],
        [1, 9, 2, 8, 4, 3, 7, 6, 5],
        [6, 1, 8, 3, 5, 4, 2, 9, 7],
        [9, 7, 4, 2, 8, 6, 5, 3, 1],
        [3, 2, 5, 1, 9, 7, 8, 4, 6],
    ];

    let sudoku2 = [
        [5, 8, 1, 6, 7, 2, 4, 3, 9],
        [7, 9, 2, 8, 4, 3, 6, 5, 1],
        [3, 6, 4, 5, 9, 1, 7, 8, 2],
        [4, 3, 8, 9, 5, 7, 2, 1, 6],
        [2, 5, 6, 1, 8, 4, 9, 7, 3],
        [1, 7, 9, 3, 2, 6, 8, 4, 5],
        [8, 4, 5, 2, 1, 9, 3, 6, 7],
        [9, 1, 3, 7, 6, 8, 5, 2, 4],
        [6, 2, 7, 4, 3, 5, 1, 9, 8],
    ];

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    let circuit1 = SudokuCircuit { sudoku: sudoku1 };
    let circuit2 = SudokuCircuit { sudoku: sudoku2 };
    let circuit3 = TrivialValidityPredicateCircuit::dummy(&mut OsRng);

    const K: u32 = 13;

    println!("Building proving key 1... ");
    let time = Instant::now();
    let vk1 = VerifyingKey::build(&circuit1, K);
    println!("Done in {} ms", time.elapsed().as_millis());
    let vk1s = format!("{:?}", vk1.vk.pinned());

    println!("Building proving key 2... ");
    let time = Instant::now();
    let vk2 = VerifyingKey::build(&circuit2, K);
    println!("Done in {} ms", time.elapsed().as_millis());
    let vk2s = format!("{:?}", vk2.vk.pinned());

    // Verif keys for Sudoku circuits should be the same even though the puzzles are different
    assert_eq!(vk1s, vk2s);
    assert_eq!(calculate_hash(&vk1), calculate_hash(&vk2));

    println!("Building proving key 3... ");
    let time = Instant::now();
    let vk3 = VerifyingKey::build(&circuit3, K);
    println!("Done in {} ms", time.elapsed().as_millis());
    let vk3s = format!("{:?}", vk3.vk.pinned());

    // Sudoku circuit and Trivial VP Circuit are different, so verif keys should be different
    assert_ne!(vk1s, vk3s);
    assert_ne!(calculate_hash(&vk1), calculate_hash(&vk3));

    println!("Building proving key 4... ");
    let time = Instant::now();
    let vk4 = VerifyingKey::build(&circuit3, K+3);
    println!("Done in {} ms", time.elapsed().as_millis());
    let vk4s = format!("{:?}", vk4.vk.pinned());

    // Verif keys with different K should be different
    assert_ne!(vk4s, vk3s);
    assert_ne!(calculate_hash(&vk4), calculate_hash(&vk3));

    // TODO: Add actual hashset tests
}
