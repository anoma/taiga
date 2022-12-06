
use halo2_proofs::{
    plonk::{ConstraintSystem},
};
use pasta_curves::{pallas};


extern crate taiga_halo2;
use taiga_halo2::{
    circuit::{
        note_circuit::NoteConfig,
        vp_circuit::{ValidityPredicateCircuit, ValidityPredicateConfig},
    },
    constant::NUM_NOTE,
    note::Note,
};

use crate::app::valid_sudoku::circuit::{SudokuCircuit};

#[derive(Clone, Debug)]
pub struct SudokuVPConfig {
    note_config: NoteConfig,
}

impl ValidityPredicateConfig for SudokuVPConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_config.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_config = Self::configure_note(meta);
        Self { note_config }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SudokuVP {
    pub sudoku: SudokuCircuit,
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
}

impl ValidityPredicateCircuit for SudokuVP {
    type Config = SudokuVPConfig;

    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }
}

impl SudokuVP {
    pub fn new(
        sudoku: SudokuCircuit,
        spend_notes: [Note; NUM_NOTE],
        output_notes: [Note; NUM_NOTE],
    ) -> Self {
        Self {
            sudoku,
            spend_notes,
            output_notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use taiga_halo2::{
        application::Application,
        circuit::gadgets::{
            assign_free_advice, assign_free_instance, AddChip, AddConfig, AddInstructions, MulChip,
            MulConfig, MulInstructions, SubChip, SubConfig, SubInstructions,
        },
        constant::NUM_NOTE,
        note::Note,
        nullifier::Nullifier,
        user::User,
        vp_description::ValidityPredicateDescription,
    };

    use ff::Field;
    use pasta_curves::pallas;
    use rand::{rngs::OsRng, Rng};

    use crate::app::valid_sudoku::{circuit::SudokuCircuit, vp::SudokuVP};
    use crate::keys::VerifyingKey;

    #[test]
    fn test_vp() {
        // TODO: What do notes contain in Sudoku?
        let mut rng = OsRng;
        let input_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::dummy(&mut rng));

        const K: u32 = 13;
        let sudoku = SudokuCircuit {
            sudoku: [
                [7, 6, 9, 5, 3, 8, 1, 2, 4],
                [2, 4, 3, 7, 1, 9, 6, 5, 8],
                [8, 5, 1, 4, 6, 2, 9, 7, 3],
                [4, 8, 6, 9, 7, 5, 3, 1, 2],
                [5, 3, 7, 6, 2, 1, 4, 8, 9],
                [1, 9, 2, 8, 4, 3, 7, 6, 5],
                [6, 1, 8, 3, 5, 4, 2, 9, 7],
                [9, 7, 4, 2, 8, 6, 5, 3, 1],
                [3, 2, 5, 1, 9, 7, 8, 4, 6],
            ],
        };

        let mut vp = SudokuVP::new(sudoku.clone(), input_notes, output_notes);

        let vk = VerifyingKey::build(&sudoku, K);

        let vp_desc = ValidityPredicateDescription::from_vk(vk.vk);

        let vp_data = pallas::Base::zero(); // TODO: What else can this be?

        let user = User::dummy(&mut rng);
        let application = Application::new(vp_desc, vp_data, user);

        let value: u64 = 1; // TODO: What is the correct value here (if any)?
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        Note::new(application, value, rho, psi, rcm, true);
    }
}
