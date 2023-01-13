use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{self, create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
    transcript::Blake2bWrite,
};
use pasta_curves::{pallas, vesta};

extern crate taiga_halo2;
use taiga_halo2::{
    circuit::{
        integrity::{OutputNoteVar, SpendNoteVar},
        note_circuit::NoteConfig,
        vp_circuit::{
            VPVerifyingInfo, ValidityPredicateCircuit, ValidityPredicateConfig,
            ValidityPredicateInfo,
        },
    },
    constant::{NUM_NOTE, SETUP_PARAMS_MAP},
    note::Note,
    vp_circuit_impl,
    vp_description::ValidityPredicateDescription,
};

use crate::app::valid_sudoku::circuit::{SudokuCircuit, SudokuConfig};
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct SudokuVPConfig {
    note_config: NoteConfig,
    sudoku_config: SudokuConfig,
}

impl ValidityPredicateConfig for SudokuVPConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_config.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_config = Self::configure_note(meta);
        let sudoku_config = SudokuCircuit::configure(meta);
        Self {
            note_config,
            sudoku_config,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SudokuVP {
    pub sudoku: SudokuCircuit,
    spend_notes: [Note; NUM_NOTE],
    output_notes: [Note; NUM_NOTE],
}

impl ValidityPredicateCircuit for SudokuVP {
    type VPConfig = SudokuVPConfig;

    fn custom_constraints(
        &self,
        config: Self::VPConfig,
        layouter: impl Layouter<pallas::Base>,
        _spend_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), plonk::Error> {
        self.sudoku.synthesize(config.sudoku_config, layouter)
    }
}

impl ValidityPredicateInfo for SudokuVP {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE] {
        &self.spend_notes
    }

    fn get_output_notes(&self) -> &[Note; NUM_NOTE] {
        &self.output_notes
    }

    fn get_instances(&self) -> Vec<pallas::Base> {
        self.get_note_instances()
    }

    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
        let instance = self.get_instances();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        create_proof(
            params,
            &pk,
            &[self.clone()],
            &[&[&instance]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        VPVerifyingInfo {
            vk,
            proof,
            instance,
        }
    }

    fn get_vp_description(&self) -> ValidityPredicateDescription {
        let params = SETUP_PARAMS_MAP.get(&12).unwrap();
        let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
        ValidityPredicateDescription::from_vk(vk)
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

vp_circuit_impl!(SudokuVP);

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use taiga_halo2::{
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
    use pasta_curves::pallas::{self, Point};
    use rand::{rngs::OsRng, Rng};
    use std::collections::hash_map::DefaultHasher;
    use crate::app::valid_sudoku::{circuit::SudokuCircuit, vp::SudokuVP};
    use crate::keys::VerifyingKey;

    use crate::vp_table::VPTable;
    use std::collections::HashMap;
    use std::hash::{Hash, Hasher};
    use pasta_curves::Fp;
    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }
    #[test]
    fn test_vp() {
        const K: u32 = 13;
        let mut vp = SudokuVP::default();
        let vk = VerifyingKey::build(&vp, K);


        let vp_desc = ValidityPredicateDescription::from_vk(vk.vk);

        let vk_hash = calculate_hash(&vp_desc);
        let vp_data = Fp::from(vk_hash); // TODO: Hash user and value as well

        let mut rng = OsRng;
        let user = User::dummy(&mut rng);

        let value: u64 = 1; 
        let rcm = pallas::Scalar::random(&mut rng);
        let psi = pallas::Base::random(&mut rng);
        let rho = Nullifier::new(pallas::Base::random(&mut rng));
        Note::new(vp_desc, value, rho, psi, rcm, true, vp_data, user, vec![]);
    }
}
