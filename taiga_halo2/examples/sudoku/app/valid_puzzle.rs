extern crate taiga_halo2;
use ff::PrimeField;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner, AssignedCell, Layouter, Value},
    plonk::{self, Advice, Column, Instance as InstanceColumn},
};
use pasta_curves::{pallas, Fp};

use taiga_halo2::circuit::gadgets::{
    assign_free_advice, AddChip, AddConfig, AddInstructions, SubChip, SubConfig, SubInstructions, MulChip, MulConfig, MulInstructions,
};

use ff::Field;

#[derive(Clone, Debug)]
pub struct SudokuConfig {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 5],
    add_config: AddConfig,
    sub_config: SubConfig,
    mul_config: MulConfig,
}

impl SudokuConfig {
    pub(super) fn add_chip(&self) -> AddChip<pallas::Base> {
        AddChip::construct(self.add_config.clone(), ())
    }

    pub(super) fn sub_chip(&self) -> SubChip<pallas::Base> {
        SubChip::construct(self.sub_config.clone(), ())
    }

    pub(super) fn mul_chip(&self) -> MulChip<pallas::Base> {
        MulChip::construct(self.mul_config.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct PuzzleCircuit {
    pub sudoku: [[u8; 9]; 9],
}

// It will check that all rows, columns, and squares are valid, that is, they contain all numbers from 1 to 9
impl plonk::Circuit<pallas::Base> for PuzzleCircuit {
    type Config = SudokuConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Addition of two field elements.
        let add_config = AddChip::configure(meta, [advices[0], advices[1]]);
        let sub_config = SubChip::configure(meta, [advices[0], advices[1]]);

        // Multiplication of two field elements.
        let mul_config = MulChip::configure(meta, [advices[0], advices[1]]);

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        SudokuConfig {
            primary,
            advices,
            add_config,
            sub_config,
            mul_config,
        }
    }

    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        /*
        Check that:
            - Every entry in the sudoku puzzle is a number from 0 to 9
            - Numbers from 1 to 9 do not repeat on each row, column and square
            - The sum of revealed entries (i.e. entries that contain numbers from 1 to 9) is at least 17, since this is required for a puzzle to be solvable
        */

        let sudoku_cells: Vec<AssignedCell<_, _>> = self
            .sudoku
            .concat()
            .iter()
            .map(|x| {
                assign_free_advice(
                    layouter.namespace(|| "sudoku_cell"),
                    config.advices[0],
                    Value::known(pallas::Base::from_u128(*x as u128)),
                )
                .unwrap()
            })
            .collect();

        // cells for (1..10)
        let cell_integers: Vec<AssignedCell<_, _>> = (1..10)
            .map(|i| {
                assign_free_advice(
                    layouter.namespace(|| "cell i"),
                    config.advices[0],
                    Value::known(pallas::Base::from(i)),
                )
                .unwrap()
            })
            .collect();

        // Check that every entry in the sudoku puzzle is a number from 0 to 9
        let sudoku_cells_reduced: Vec<AssignedCell<_, _>> = self
            .sudoku
            .concat()
            .into_iter()
            .filter(|x| *x < 10)
            .map(|x| {
                assign_free_advice(
                    layouter.namespace(|| "sudoku_cell"),
                    config.advices[0],
                    Value::known(pallas::Base::from_u128(x as u128)),
                )
                .unwrap()
            })
            .collect();

        let cell_lhs = assign_free_advice(
            layouter.namespace(|| "lhs init"),
            config.advices[0],
            Value::known(Fp::from(sudoku_cells_reduced.len() as u64)),
        )
        .unwrap();
        let cell_rhs = assign_free_advice(
            layouter.namespace(|| "rhs init"),
            config.advices[1],
            Value::known(-Fp::from(81)),
        )
        .unwrap();

        let expected_zero = AddInstructions::add(
            &config.add_chip(),
            layouter.namespace(|| "final add"),
            &cell_lhs,
            &cell_rhs,
        )
        .unwrap();

        layouter
            .constrain_instance(expected_zero.cell(), config.primary, 0)
            .unwrap();

        // Check that numbers from 1 to 9 do not repeat on each row, column and square
        // The idea is that once we filter the zeroes (i.e. the non-revealed numbers of the puzzle),
        // a list has unique elements if the product of the differences of all pairs of elements is not zero.
        // That is Prod(l[i] - l[j]) != 0 if i != j
        // E.g. [0, 0, 1, 3, 7, 0, 4, 8, 0] turns into [1,3,7,4,8]
        // and (1-3)(1-7)(1-4)(1-8)
        //          (3-7)(3-4)(3-8)
        //               (7-4)(7-8)
        //                    (4-8) =? 0
        // This is computed in n! operations
        let non_zero_sudoku_cells: Vec<AssignedCell<_, _>> = self
            .sudoku
            .concat()
            .into_iter()
            .enumerate()
            .map(|(i, x)| {
                if (x == 0) {
                    assign_free_advice(
                        layouter.namespace(|| "non-zero sudoku_cell"),
                        config.advices[0],
                        Value::known(pallas::Base::from_u128(10 * i as u128)),
                    )
                    .unwrap()
                } else {
                    assign_free_advice(
                        layouter.namespace(|| "non-zero sudoku_cell"),
                        config.advices[0],
                        Value::known(pallas::Base::from_u128(x as u128)),
                    )
                    .unwrap()
                }
            })
            .collect();

        // rows
        let rows: Vec<Vec<AssignedCell<Fp, Fp>>> =
        non_zero_sudoku_cells.chunks(9).map(|row| row.to_vec()).collect();
        // cols
        let cols: Vec<Vec<AssignedCell<Fp, Fp>>> = (1..10)
            .map(|i| {
                let col: Vec<AssignedCell<Fp, Fp>> = non_zero_sudoku_cells
                    .chunks(9)
                    .map(|row| row[i - 1].clone())
                    .collect();
                col
            })
            .collect();
        // small squares
        let mut squares: Vec<Vec<AssignedCell<Fp, Fp>>> = vec![];
        for i in 1..4 {
            for j in 1..4 {
                let sub_lines = &rows[(i - 1) * 3..i * 3];
    
                let square: Vec<&[AssignedCell<Fp, Fp>]> = sub_lines
                    .iter()
                    .map(|line| &line[(j - 1) * 3..j * 3])
                    .collect();
                squares.push(square.concat());
            }
        }

        for (cpt, perm) in [rows, cols, squares].concat().iter().enumerate() {
            let mut cell_lhs = assign_free_advice(
                layouter.namespace(|| "lhs init"),
                config.advices[0],
                Value::known(Fp::one()),
            )
            .unwrap();
            for i in 0..9 {
                for j in (i+1)..9 {
                    let diff = SubInstructions::sub(
                        &config.sub_chip(),
                        layouter.namespace(|| "diff"),
                        &perm[i],
                        &perm[j],
                    )
                    .unwrap();
                    cell_lhs = MulInstructions::mul(
                        &config.mul_chip(),
                        layouter.namespace(|| "lhs * diff"),
                        &cell_lhs,
                        &diff,
                    )
                    .unwrap();
                }
            }
            let cell_lhs_inv = assign_free_advice(
                layouter.namespace(|| "non-zero sudoku_cell"),
                config.advices[0],
                cell_lhs.value().map(|x| x.invert().unwrap()),
            ).unwrap();

            let cell_div = MulInstructions::mul(
                &config.mul_chip(),
                layouter.namespace(|| "lhs * 1/lhs"),
                &cell_lhs,
                &cell_lhs_inv,
            )
            .unwrap();

 
            layouter
                .constrain_instance(cell_div.cell(), config.primary, 1)
                .unwrap();
        }


        // Check that the sum of revealed entries (i.e. entries that contain numbers from 1 to 9) is at least 17, since this is required for a puzzle to be solvable
        let mut counter = 0;
        for i in self.sudoku.concat() {
            if (i != 0) {
                counter = counter + 1;
            }
        }

        let cell_counter = assign_free_advice(
            layouter.namespace(|| "counter"),
            config.advices[0],
            Value::known(pallas::Base::from_u128(counter as u128)),
        )
        .unwrap();


        let mut cell_lhs = assign_free_advice(
            layouter.namespace(|| "lhs init"),
            config.advices[0],
            Value::known(Fp::one()),
        )
        .unwrap();

        for i in 17..82 {
            let cell_rhs = assign_free_advice(
                layouter.namespace(|| "rhs"),
                config.advices[0],
                Value::known(pallas::Base::from_u128(i as u128)),
            )
            .unwrap();

            let diff = SubInstructions::sub(
                &config.sub_chip(),
                layouter.namespace(|| "diff"),
                &cell_counter,
                &cell_rhs,
            )
            .unwrap();

            cell_lhs = MulInstructions::mul(
                &config.mul_chip(),
                layouter.namespace(|| "lhs * diff"),
                &cell_lhs,
                &diff,
            )
            .unwrap();
        }

        layouter
                .constrain_instance(cell_lhs.cell(), config.primary, 0)
                .unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use halo2_proofs::dev::MockProver;
    use pasta_curves::pallas;
    use rand::rngs::OsRng;

    use crate::{
        app::valid_puzzle::PuzzleCircuit,
        keys::{ProvingKey, VerifyingKey},
        proof::Proof,
    };

    #[test]
    fn test_puzzle() {
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
        let circuit = PuzzleCircuit { sudoku: puzzle };
        const K: u32 = 13;
        let public_inputs = [pallas::Base::zero(), pallas::Base::one()];
        assert_eq!(
            MockProver::run(K, &circuit, vec![vec![pallas::Base::zero(), pallas::Base::one()]])
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

        let proof = Proof::create(&pk, circuit, &[&public_inputs], &mut rng).unwrap();
        println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());
    
        let time = Instant::now();
        assert!(proof.verify(&vk, &[&public_inputs]).is_ok());
        println!(
            "verification: \t\t{:?}ms",
            (Instant::now() - time).as_millis()
        );
    }
}