extern crate taiga_halo2;

use halo2_gadgets::utilities::ternary;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner, AssignedCell, Layouter, Region, Value},
    plonk::{
        self, Advice, Column, ConstraintSystem, Constraints, Error, Expression,
        Instance as InstanceColumn, Selector,
    },
    poly::Rotation,
};
use pasta_curves::{pallas, Fp};

use taiga_halo2::circuit::gadgets::{
    assign_free_advice, AddChip, AddConfig, MulChip, MulConfig, MulInstructions, SubChip,
    SubConfig, SubInstructions,
};

use ff::Field;

#[derive(Clone, Debug)]
pub struct SudokuConfig {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 5],
    #[allow(dead_code)]
    add_config: AddConfig,
    sub_config: SubConfig,
    mul_config: MulConfig,
    x: Column<Advice>,
    i: Column<Advice>,
    ret: Column<Advice>,
    cond: Selector,
}

impl SudokuConfig {
    #[allow(dead_code)]
    pub(super) fn add_chip(&self) -> AddChip<pallas::Base> {
        AddChip::construct(self.add_config.clone(), ())
    }

    pub(super) fn sub_chip(&self) -> SubChip<pallas::Base> {
        SubChip::construct(self.sub_config.clone(), ())
    }

    pub(super) fn mul_chip(&self) -> MulChip<pallas::Base> {
        MulChip::construct(self.mul_config.clone())
    }

    #[allow(dead_code)]
    fn create_condition_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("condition", |meta| {
            // 1. We get x and x_inv from the column `self.x` at `cur` and `next`
            // 2. We create an expression corresponding to the boolean 1-x*x_inv
            // 4. We impose the corresponding constraint
            let cond = meta.query_selector(self.cond);
            let x = meta.query_advice(self.x, Rotation::cur());
            let i = meta.query_advice(self.i, Rotation::cur());
            let x_inv = meta.query_advice(self.x, Rotation::next());
            let ret = meta.query_advice(self.ret, Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());
            let ten = Expression::Constant(pallas::Base::from(10));
            let x_is_zero = one - x.clone() * x_inv;
            // The same to:  let poly = ret - ternary(x_is_zero, twelve, thirtyfour);
            let poly = ternary(x_is_zero.clone(), ret.clone() - (ten + i), ret - x.clone());

            Constraints::with_selector(
                cond,
                [("x is zero", x * x_is_zero), ("12 if x=0 else 34", poly)],
            )
        });
    }

    pub fn assign_region(
        &self,
        x: &AssignedCell<pallas::Base, pallas::Base>,
        i: usize,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        // this function set the value of x, and also of x_inv, needed for the circuit
        self.cond.enable(region, offset).unwrap();
        let x_inv = x
            .value()
            .map(|x| x.invert().unwrap_or(pallas::Base::zero()));
        region.assign_advice(|| "x_inv", self.x, offset + 1, || x_inv)?;

        let ret = x.value().map(|x| {
            if *x == Fp::zero() {
                Fp::from_u128(10 + i as u128)
            } else {
                *x
            }
        });
        let ret_final = region.assign_advice(|| "ret", self.ret, offset, || ret)?;
        Ok(ret_final)
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

        let x = meta.advice_column();
        meta.enable_equality(x);

        let i = meta.advice_column();
        meta.enable_equality(i);

        let ret = meta.advice_column();
        meta.enable_equality(ret);

        let cond = meta.selector();

        SudokuConfig {
            primary,
            advices,
            x,
            i,
            ret,
            cond,
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

        // Check that every entry in the sudoku puzzle is a number from 0 to 9

        let mut cell_lhs = assign_free_advice(
            layouter.namespace(|| "lhs init"),
            config.advices[0],
            Value::known(Fp::one()),
        )
        .unwrap();
        self.sudoku.concat().into_iter().for_each(|x| {
            let sudoku_cell = assign_free_advice(
                layouter.namespace(|| "sudoku_cell"),
                config.advices[0],
                Value::known(pallas::Base::from_u128(x as u128)),
            )
            .unwrap();

            for i in 0..10 {
                let valid_number_cell = assign_free_advice(
                    layouter.namespace(|| "valid number"),
                    config.advices[0],
                    Value::known(Fp::from(i as u64)),
                )
                .unwrap();

                let diff = SubInstructions::sub(
                    &config.sub_chip(),
                    layouter.namespace(|| "diff"),
                    &sudoku_cell,
                    &valid_number_cell,
                )
                .unwrap();

                cell_lhs = MulInstructions::mul(
                    &config.mul_chip(),
                    layouter.namespace(|| "lhs * (x - i)"),
                    &cell_lhs,
                    &diff,
                )
                .unwrap();
            }
        });

        layouter
            .constrain_instance(cell_lhs.cell(), config.primary, 0)
            .unwrap();

        // Check that numbers from 1 to 9 do not repeat on each row, column and square
        // The idea is that once we filter the zeroes (i.e. the non-revealed numbers of the puzzle),
        // a list has unique elements if the product of the differences of all pairs of elements is not zero.
        // That is Prod(l[i] - l[j]) != 0 if i != j
        // E.g. [0, 0, 1, 3, 7, 0, 4, 8, 0] turns into [10, 11, 1, 3, 7, 15, 4, 8, 18]
        let non_zero_sudoku_cells: Vec<AssignedCell<Fp, Fp>> = self
            .sudoku
            .concat()
            .into_iter()
            .enumerate()
            .map(|(i, x)| {
                let x_cell = assign_free_advice(
                    layouter.namespace(|| "non-zero sudoku_cell"),
                    config.x,
                    Value::known(pallas::Base::from_u128(x as u128)),
                )
                .unwrap();

                assign_free_advice(
                    layouter.namespace(|| "non-zero sudoku_cell"),
                    config.i,
                    Value::known(pallas::Base::from_u128(i as u128)),
                )
                .unwrap();

                layouter
                    .assign_region(
                        || "x cell",
                        |mut region| config.assign_region(&x_cell, i, 0, &mut region),
                    )
                    .unwrap()
            })
            .collect();

        // rows
        let rows: Vec<Vec<AssignedCell<Fp, Fp>>> = non_zero_sudoku_cells
            .chunks(9)
            .map(|row| row.to_vec())
            .collect();
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

        for perm in [rows, cols, squares].concat().iter() {
            let mut cell_lhs = assign_free_advice(
                layouter.namespace(|| "lhs init"),
                config.advices[0],
                Value::known(Fp::one()),
            )
            .unwrap();
            for i in 0..9 {
                for j in (i + 1)..9 {
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
            )
            .unwrap();

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
            if i != 0 {
                counter += 1;
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
    use halo2_proofs::{
        plonk::{self, ProvingKey, VerifyingKey},
        poly::commitment::Params
    };

    use crate::{
        app::valid_puzzle::circuit::PuzzleCircuit,
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
        const K: u32 = 14;
        let public_inputs = [pallas::Base::zero(), pallas::Base::one()];
        assert_eq!(
            MockProver::run(
                K,
                &circuit,
                vec![vec![pallas::Base::zero(), pallas::Base::one()]]
            )
            .unwrap()
            .verify(),
            Ok(())
        );

        println!("Success!");

        let time = Instant::now();
        let params = Params::new(K);

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();
        println!(
            "key generation: \t{:?}ms",
            (Instant::now() - time).as_millis()
        );

        let mut rng = OsRng;
        let time = Instant::now();

        let proof = Proof::create(&pk, &params, circuit, &[&public_inputs], &mut rng).unwrap();
        println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

        let time = Instant::now();
        assert!(proof.verify(&vk, &params, &[&public_inputs]).is_ok());
        println!(
            "verification: \t\t{:?}ms",
            (Instant::now() - time).as_millis()
        );
    }
}
