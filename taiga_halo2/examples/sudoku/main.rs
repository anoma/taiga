pub mod app;
pub mod keys;
pub mod proof;

fn main() {
    use std::time::Instant;

    use halo2_proofs::dev::MockProver;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    use crate::{
        app::AppCircuit,
        proof::Proof,
        keys::{VerifyingKey, ProvingKey}
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

    let circuit = AppCircuit { sudoku };
    const K: u32 = 13;
    assert_eq!(
        MockProver::run(13, &circuit, vec![vec![pallas::Base::zero(); 27]])
            .unwrap()
            .verify(),
        Ok(())
    );

    let time = Instant::now();
    let vk = VerifyingKey::build(&circuit, K);
    let pk = ProvingKey::build(&circuit, K);
    println!(
        "key generation: \t{:?}ms",
        (Instant::now() - time).as_millis()
    );

    let mut rng = OsRng;
    let time = Instant::now();
    let proof = Proof::create(&pk, circuit, &[&[pallas::Base::zero(); 27]], &mut rng).unwrap();
    println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

    let time = Instant::now();
    assert!(proof.verify(&vk, &[&[pallas::Base::zero(); 27]]).is_ok());
    println!(
        "verification: \t\t{:?}ms",
        (Instant::now() - time).as_millis()
    );
}