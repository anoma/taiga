use crate::{
    circuit::{
        gadgets::AddChip,
        integrity::{check_output_note, check_spend_note, OutputNoteVar, SpendNoteVar},
        note_circuit::{NoteCommitmentChip, NoteConfig},
    },
    constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain, NUM_NOTE,
    },
    note::Note,
};
use halo2_gadgets::{ecc::chip::EccChip, sinsemilla::chip::SinsemillaChip};
use halo2_proofs::{circuit::Layouter, plonk::Error};
use pasta_curves::pallas;

pub trait ValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig;
}
pub trait ValidityPredicateCircuit {
    type Config: ValidityPredicateConfig + Clone;
    // Default implementation, constrains the notes integrity.
    // TODO: how to enforce the constraints in vp circuit?
    fn basic_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(Vec<SpendNoteVar>, Vec<OutputNoteVar>), Error> {
        let note_config = config.get_note_config();
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::<
            NoteCommitmentHashDomain,
            NoteCommitmentDomain,
            NoteCommitmentFixedBases,
        >::load(note_config.sinsemilla_config.clone(), &mut layouter)?;

        // Construct a Sinsemilla chip
        let sinsemilla_chip = SinsemillaChip::construct(note_config.sinsemilla_config.clone());

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(note_config.ecc_config);

        // Construct a NoteCommit chip
        let note_commit_chip =
            NoteCommitmentChip::construct(note_config.note_commit_config.clone());

        // Construct an add chip
        let add_chip = AddChip::<pallas::Base>::construct(note_config.add_config, ());

        let input_notes = self.get_input_notes();
        let output_notes = self.get_output_notes();
        let mut input_note_variables = vec![];
        let mut output_note_variables = vec![];
        for i in 0..NUM_NOTE {
            let input_note_var = check_spend_note(
                layouter.namespace(|| "check spend note"),
                note_config.advices,
                note_config.instances,
                ecc_chip.clone(),
                sinsemilla_chip.clone(),
                note_commit_chip.clone(),
                note_config.poseidon_config.clone(),
                add_chip.clone(),
                input_notes[i].clone(),
            )?;
            let output_note_var = check_output_note(
                layouter.namespace(|| "check output note"),
                note_config.advices,
                ecc_chip.clone(),
                sinsemilla_chip.clone(),
                note_commit_chip.clone(),
                note_config.poseidon_config.clone(),
                output_notes[i].clone(),
                input_note_var.nf.clone(),
            )?;
            input_note_variables.push(input_note_var);
            output_note_variables.push(output_note_var);
        }

        Ok((input_note_variables, output_note_variables))
    }

    // VP designer need to implement the following functions.
    // `get_input_notes` and `get_output_notes` will be used in `basic_constraints` to get the basic note info.
    fn get_input_notes(&self) -> &[Note; NUM_NOTE];
    fn get_output_notes(&self) -> &[Note; NUM_NOTE];
    // Add custom constraints on basic note variables and user-defined variables.
    fn custom_constraints(
        &self,
        _config: Self::Config,
        mut _layouter: impl Layouter<pallas::Base>,
        _input_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), Error> {
        Ok(())
    }
}
