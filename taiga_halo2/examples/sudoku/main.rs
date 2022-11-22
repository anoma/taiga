pub mod app;
pub mod keys;
pub mod proof;

fn main() {
    use std::time::Instant;

    use halo2_proofs::dev::MockProver;
    use pasta_curves::{pallas, {arithmetic::FieldExt}};
    use rand::rngs::OsRng;

    use crate::{
        app::valid_sudoku::SudokuCircuit,
        keys::{ProvingKey, VerifyingKey},
        proof::Proof,
    };

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
        .map(|cell| pallas::Base::from_u128(*cell as u128)).collect();
    let circuit = SudokuCircuit { sudoku };

    const K: u32 = 13;
    let zero = pallas::Base::zero();
    let mut pub_instance_vec = vec![zero];
    pub_instance_vec.append(&mut vec_puzzle);
    // println!("{:?}", vec![pub_instance_vec]);
    // println!("{:?}", vec![vec![zero; 82]]);
    assert_eq!(
        MockProver::run(
            13, 
            &circuit,
            vec![pub_instance_vec])
            // vec![vec![zero; 82]])
            .unwrap()
            .verify(),
        Ok(())
    );

    println!("Success!");
    let time = Instant::now();
    let vk = VerifyingKey::build(&circuit, K);
    let pk = ProvingKey::build(&circuit, K);
    println!(
        "key generation: \t{:?}ms",
        (Instant::now() - time).as_millis()
    );

    let mut rng = OsRng;
    let time = Instant::now();
    let proof = Proof::create(&pk, circuit, &[&[pallas::Base::zero()]], &mut rng).unwrap();
    println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

    let time = Instant::now();
    assert!(proof.verify(&vk, &[&[pallas::Base::zero()]]).is_ok());
    println!(
        "verification: \t\t{:?}ms",
        (Instant::now() - time).as_millis()
    );
}
