use ff::PrimeField;
use halo2_proofs::{
    circuit::{floor_planner, AssignedCell, Layouter, Value},
    plonk::{self, Advice, Column, Instance as InstanceColumn},
};
use pasta_curves::{pallas, Fp};

extern crate taiga_halo2;
use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, P128Pow5T3},
    Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
};
use taiga_halo2::circuit::gadgets::{
    add::{AddChip, AddConfig, AddInstructions},
    assign_free_advice, assign_free_instance,
    mul::{MulChip, MulConfig, MulInstructions},
    sub::{SubChip, SubConfig, SubInstructions},
};

#[derive(Clone, Debug)]
pub struct SudokuConfig {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 5],
    add_config: AddConfig,
    sub_config: SubConfig,
    mul_config: MulConfig,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
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

    pub(super) fn poseidon_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub struct SudokuCircuit {
    pub sudoku: [[u8; 9]; 9],
}

// It will check that all rows, columns, and squares are valid, that is, they contain all numbers from 1 to 9
impl plonk::Circuit<pallas::Base> for SudokuCircuit {
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

        // Poseidon requires four advice columns, while ECC incomplete addition requires
        // six, so we could choose to configure them in parallel. However, we only use a
        // single Poseidon invocation, and we have the rows to accommodate it serially.
        // Instead, we reduce the proof size by sharing fixed columns between the ECC and
        // Poseidon chips.
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        // Configuration for the Poseidon hash.
        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[0..3].try_into().unwrap(),
            advices[4],
            rc_a,
            rc_b,
        );

        SudokuConfig {
            primary,
            advices,
            add_config,
            sub_config,
            mul_config,
            poseidon_config,
        }
    }

    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        /*
        The circuit splits into:
        1. Creating two field elements corresponding to the sudoku grid: 81 integers between 0 and 8 fits in 81*4=324 bits, which can be stored into two 256-bit field elements.
        2. Create gamma using the Poseidon hash with the two field elements of step 1.
        3. Check that all lines, rows and small squares are actually permutation of (1..10) using the result of the PLONK paper.
        */

        //
        // STEP 1
        //

        let sudoku = self.sudoku.concat();
        let s1 = &sudoku[..sudoku.len() / 2]; // s1 contains 40 elements
        let s2 = &sudoku[sudoku.len() / 2..]; // s2 contains 41 elements
        let u: Vec<u8> = s1
            .iter()
            .zip(s2.iter()) // zip contains 40 elements
            .map(|(b1, b2)| {
                // Two entries of the sudoku can be seen as [b0,b1,b2,b3] and [c0,c1,c2,c3]
                // We store [b0,b1,b2,b3,c0,c1,c2,c3] here.
                assert!(b1 + 16 * b2 < 255);
                b1 + 16 * b2
            })
            .chain(s2.last().copied()) // there's 41st element in s2, so we add it here
            .collect();

        // fill u with zeros.
        // The length of u is 41 bytes, or 328 bits, since we are allocating 4 bits
        // per the first 40 integers and let the last sudoku digit takes an entire byte.
        // We still need to add 184 bits (i.e. 23 bytes) to reach 2*256=512 bits in total.
        // let u2 = [u, vec![0; 23]].concat(); // this is not working with all puzzles
        // For some reason, not _any_ byte array can be transformed into a 256-bit field element.
        // Preliminary investigation shows that `pallas::Base::from_repr` fails on a 32 byte array
        // if the first bit of every 8-byte (== u64) chunk is set to '1'. For now, we just add a zero
        // byte every 7 bytes, which is not ideal but works. Further investigation is needed.
        let mut u2 = [0u8; 64];
        let mut i = 0;
        let mut j = 0;
        while j != u.len() {
            if (i + 1) % 8 != 0 {
                u2[i] = u[j];
                j += 1;
            }
            i += 1;
        }
        let u_first: [u8; 32] = u2[0..32].try_into().unwrap();
        let u_last: [u8; 32] = u2[32..].try_into().unwrap();

        let x = pallas::Base::from_repr(u_first).unwrap();
        let y = pallas::Base::from_repr(u_last).unwrap();

        let x_cell = assign_free_advice(
            layouter.namespace(|| "x"),
            config.advices[0],
            Value::known(x),
        )?;
        let y_cell = assign_free_advice(
            layouter.namespace(|| "y"),
            config.advices[1],
            Value::known(y),
        )?;

        //
        // STEP 2
        //

        // gamma = Poseidon(x, y)
        let gamma = {
            let poseidon_message: [AssignedCell<pallas::Base, pallas::Base>; 2] = [x_cell, y_cell];

            // let poseidon_message = [u[0], u[1]];
            let poseidon_hasher = halo2_gadgets::poseidon::Hash::<_, _, P128Pow5T3, _, 3, 2>::init(
                config.poseidon_chip(),
                layouter.namespace(|| "Poseidon init"),
            )?;
            poseidon_hasher.hash(
                layouter.namespace(|| "Poseidon hash (x, y)"),
                poseidon_message,
            )?
        };

        //
        // STEP 3
        //
        // cells for the sudoku entries.
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

        // rows
        let rows: Vec<Vec<AssignedCell<Fp, Fp>>> =
            sudoku_cells.chunks(9).map(|row| row.to_vec()).collect();
        // cols
        let cols: Vec<Vec<AssignedCell<Fp, Fp>>> = (1..10)
            .map(|i| {
                let col: Vec<AssignedCell<Fp, Fp>> = sudoku_cells
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

        // check that rows, cols and small squares are permutations of (1..10)
        for (cpt, perm) in [rows, cols, squares].concat().iter().enumerate() {
            // lhs = prod_i (i + gamma)
            // rhs = -prod_i (sigma(i) + gamma)
            // compute the circuit corresponding to lhs + rhs (should be zero)
            let mut cell_lhs = assign_free_advice(
                layouter.namespace(|| "lhs init"),
                config.advices[0],
                Value::known(Fp::one()),
            )
            .unwrap();
            let mut cell_rhs = assign_free_advice(
                layouter.namespace(|| "rhs init"),
                config.advices[1],
                Value::known(-Fp::one()),
            )
            .unwrap();
            for i in 1..10 {
                // LHS
                // t = i + gamma
                let t = AddInstructions::add(
                    &config.add_chip(),
                    layouter.namespace(|| "i+gamma"),
                    &cell_integers[i - 1],
                    &gamma,
                )
                .unwrap();
                // lhs = lhs * t
                cell_lhs = MulInstructions::mul(
                    &config.mul_chip(),
                    layouter.namespace(|| "lhs * t"),
                    &cell_lhs,
                    &t,
                )
                .unwrap();

                // RHS
                // u = sigma(i) + gamma
                let u = AddInstructions::add(
                    &config.add_chip(),
                    layouter.namespace(|| "sigma(i)+gamma"),
                    &perm[i - 1],
                    &gamma,
                )
                .unwrap();
                // rhs = rhs * u
                cell_rhs = MulInstructions::mul(
                    &config.mul_chip(),
                    layouter.namespace(|| "rhs * u"),
                    &cell_rhs,
                    &u,
                )
                .unwrap();
            }

            // We add an instance of LHS + RHS, expected to be zero
            let expected_zero = AddInstructions::add(
                &config.add_chip(),
                layouter.namespace(|| "final add"),
                &cell_lhs,
                &cell_rhs,
            )
            .unwrap();

            layouter
                .constrain_instance(expected_zero.cell(), config.primary, cpt)
                .unwrap();
        }

        // Check the solution corresponds to the given puzzle
        sudoku_cells
            .iter()
            .enumerate()
            .for_each(|(i, solution_cell)| {
                let puzzle_cell = assign_free_instance(
                    layouter.namespace(|| "instance"),
                    config.primary,
                    i + 27,
                    config.advices[0],
                )
                .unwrap();

                // puzzle_cell * (solution_cell - puzzle_cell) = 0

                let diff = SubInstructions::sub(
                    &config.sub_chip(),
                    layouter.namespace(|| "diff"),
                    solution_cell,
                    &puzzle_cell,
                )
                .unwrap();

                let expected_zero = MulInstructions::mul(
                    &config.mul_chip(),
                    layouter.namespace(|| "rhs * u"),
                    &puzzle_cell,
                    &diff,
                )
                .unwrap();

                layouter
                    .constrain_instance(expected_zero.cell(), config.primary, 0)
                    .unwrap();
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::SudokuCircuit;
    use halo2_proofs::{arithmetic::FieldExt, dev::MockProver};
    use rand::rngs::OsRng;

    use halo2_proofs::{plonk, poly::commitment::Params};
    use pasta_curves::{pallas, vesta};
    use std::time::Instant;
    use taiga_halo2::proof::Proof;
    #[test]
    fn test_sudoku() {
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

        // // ------- PLOTTING SECTION --------
        // use plotters::prelude::*;
        // let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
        // root.fill(&WHITE).unwrap();
        // let root = root
        //     .titled("Example Circuit Layout", ("sans-serif", 60))
        //     .unwrap();

        // halo2_proofs::dev::CircuitLayout::default()
        //     // You can optionally render only a section of the circuit.
        //     // .view_width(0..7)
        //     // .view_height(0..60)
        //     // You can hide labels, which can be useful with smaller areas.
        //     .show_labels(false)
        //     // Render the circuit onto your area!
        //     // The first argument is the size parameter for the circuit.
        //     .render(K, &circuit, &root)
        //     .unwrap();

        // let dot_string = halo2_proofs::dev::circuit_dot_graph(&circuit);

        // // Now you can either handle it in Rust, or just
        // // print it out to use with command-line tools.
        // print!("{}", dot_string);
        // // ---- END OF PLOTTING SECTION --------

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
        let proof =
            Proof::create(&pk, &params, circuit.clone(), &[&pub_instance], &mut rng).unwrap();
        println!("proof: \t\t\t{:?}ms", (Instant::now() - time).as_millis());

        let time = Instant::now();
        assert!(proof.verify(&vk, &params, &[&pub_instance]).is_ok());
        println!(
            "verification: \t\t{:?}ms",
            (Instant::now() - time).as_millis()
        );
    }

    #[test]
    fn test_synthesize() {
        use crate::circuit::SudokuCircuit;

        let sudoku = [
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

        const K: u32 = 13;

        let circuit = SudokuCircuit { sudoku };
        let params: Params<vesta::Affine> = Params::new(K);

        let _vk = plonk::keygen_vk(&params, &circuit).unwrap(); // this would fail on this specific puzzle with the old implementation of synthesize
    }
}
