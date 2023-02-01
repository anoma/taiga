pub mod app;

fn main() {
    use std::time::Instant;

    use halo2_proofs::{dev::MockProver, plonk, poly::commitment::Params};
    use pasta_curves::{arithmetic::FieldExt, pallas};
    use rand::rngs::OsRng;

    use crate::app::valid_sudoku::circuit::SudokuCircuit;

    use taiga_halo2::proof::Proof;

    let sudoku = [
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

    let puzzle = [
        [7, 0, 9, 5, 3, 8, 1, 2, 4],
        [2, 0, 3, 7, 1, 9, 6, 5, 8],
        [8, 0, 1, 4, 6, 2, 9, 7, 3],
        [4, 0, 6, 9, 7, 5, 3, 1, 2],
        [5, 0, 7, 6, 2, 1, 4, 8, 9],
        [1, 0, 2, 8, 4, 3, 7, 6, 5],
        [6, 0, 8, 3, 5, 4, 2, 9, 7],
        [9, 0, 4, 2, 8, 6, 5, 3, 1],
        [3, 0, 5, 1, 9, 7, 8, 4, 6],
    ];

    let mut vec_puzzle: Vec<pallas::Base> = puzzle
        .concat()
        .iter()
        .map(|cell| pallas::Base::from_u128(*cell as u128))
        .collect();

    let circuit = SudokuCircuit { sudoku };

    const K: u32 = 13;
    let zeros = [pallas::Base::zero(); 27];
    let mut pub_instance_vec = zeros.to_vec();
    pub_instance_vec.append(&mut vec_puzzle);
    assert_eq!(
        MockProver::run(K, &circuit, vec![pub_instance_vec.clone()])
            .unwrap()
            .verify(),
        Ok(())
    );
    let pub_instance: [pallas::Base; 108] = pub_instance_vec.try_into().unwrap();

    println!("Success!");
    let time = Instant::now();
    let params = Params::new(K);

    let vk = plonk::keygen_vk(&params, &circuit).unwrap();
    let pk = plonk::keygen_pk(&params, vk.clone(), &circuit).unwrap();

    println!(
        "key generation: \t{:?}ms",
        (Instant::now() - time).as_millis()
    );

    let mut rng = OsRng;
    let time = Instant::now();
    let proof = Proof::create(&pk, &params, circuit, &[&pub_instance], &mut rng).unwrap();
    println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

    let time = Instant::now();
    assert!(proof.verify(&vk, &params, &[&pub_instance]).is_ok());
    println!(
        "verification: \t\t{:?}ms",
        (Instant::now() - time).as_millis()
    );
}
