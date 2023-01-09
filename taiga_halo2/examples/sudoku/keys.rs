use halo2_proofs::{plonk::{self, Circuit}, transcript::Blake2bWrite};
use pasta_curves::{pallas, vesta};
use std::{hash::{Hash, Hasher}, collections::hash_map::DefaultHasher};

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
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        self.vk.hash_into(&mut transcript);
        transcript.finalize().hash(state);
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
    use crate::app::valid_sudoku::circuit::SudokuCircuit;
    use std::io::{stdout, Write};
    use std::time::Instant;

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

    let circuit1 = SudokuCircuit { sudoku: sudoku1 };
    let circuit2 = SudokuCircuit { sudoku: sudoku2 };
    const K: u32 = 13;

    print!("Building proving key 1... "); stdout().flush();
    let time = Instant::now();
    let vk1 = VerifyingKey::build(&circuit1, K);
    println!("Done in {} ms", time.elapsed().as_millis());

    print!("Building proving key 2... "); stdout().flush();
    let vk2 = VerifyingKey::build(&circuit1, K);
    println!("Done in {} ms", time.elapsed().as_millis());

    print!("Building proving key 3... "); stdout().flush();
    let vk3 = VerifyingKey::build(&circuit2, K);
    println!("Done in {} ms", time.elapsed().as_millis());
    println!("Done building proving keys.");

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    assert_eq!(calculate_hash(&vk1), calculate_hash(&vk2));
    assert_ne!(calculate_hash(&vk1), calculate_hash(&vk3)); // these are stil equal
}
