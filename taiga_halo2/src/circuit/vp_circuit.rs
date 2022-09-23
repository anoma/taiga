use crate::{
    circuit::{
        gadgets::{assign_free_advice, AddChip},
        integrity::{check_output_note, check_spend_note, OutputNoteVar, SpendNoteVar},
        note_circuit::{NoteChip, NoteCommitmentChip, NoteConfig},
    },
    constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain, NUM_NOTE,
    },
    note::Note,
};
use halo2_gadgets::{ecc::chip::EccChip, sinsemilla::chip::SinsemillaChip};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

use super::circuit_parameters::CircuitParameters;

pub trait ValidityPredicateConfig<CP: CircuitParameters> {
    fn configure_note(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> NoteConfig<CP> {
        let instances = meta.instance_column();
        meta.enable_equality(instances);

        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        NoteChip::configure(meta, instances, advices)
    }
    fn get_note_config(&self) -> NoteConfig<CP>;
    fn configure(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> Self;
}
pub trait ValidityPredicateCircuit<CP: CircuitParameters> {
    type Config: ValidityPredicateConfig<CP> + Clone;
    // Default implementation, constrains the notes integrity.
    // TODO: how to enforce the constraints in vp circuit?
    fn basic_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<CP::CurveScalarField>,
    ) -> Result<(Vec<SpendNoteVar<CP>>, Vec<OutputNoteVar<CP>>), Error> {
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
        let add_chip = AddChip::<CP::CurveScalarField>::construct(note_config.add_config, ());

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
                i * 2,
            )?;

            // The old_nf may not be from above input note
            let old_nf = assign_free_advice(
                layouter.namespace(|| "old nf"),
                note_config.advices[0],
                Value::known(output_notes[i].rho.inner()),
            )?;
            let output_note_var = check_output_note(
                layouter.namespace(|| "check output note"),
                note_config.advices,
                note_config.instances,
                ecc_chip.clone(),
                sinsemilla_chip.clone(),
                note_commit_chip.clone(),
                note_config.poseidon_config.clone(),
                output_notes[i].clone(),
                old_nf,
                i * 2 + 1,
            )?;
            input_note_variables.push(input_note_var);
            output_note_variables.push(output_note_var);
        }

        Ok((input_note_variables, output_note_variables))
    }

    // VP designer need to implement the following functions.
    // `get_input_notes` and `get_output_notes` will be used in `basic_constraints` to get the basic note info.
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE];
    fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE];
    // Add custom constraints on basic note variables and user-defined variables.
    fn custom_constraints(
        &self,
        _config: Self::Config,
        mut _layouter: impl Layouter<CP::CurveScalarField>,
        _input_note_variables: &[SpendNoteVar<CP>],
        _output_note_variables: &[OutputNoteVar<CP>],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[macro_export]
macro_rules! vp_circuit_impl {
    ($name:ident, $cp:ident) => {
        use halo2_proofs::{
            circuit::Layouter,
            plonk::{Circuit, Error},
        };
        impl<$cp: CircuitParameters> Circuit<CP::CurveScalarField> for $name {
            type Config = <Self as ValidityPredicateCircuit<CP>>::Config;
            type FloorPlanner = floor_planner::V1;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> Self::Config {
                Self::Config::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<CP::CurveScalarField>,
            ) -> Result<(), Error> {
                let (input_note_variables, output_note_variables) = self.basic_constraints(
                    config.clone(),
                    layouter.namespace(|| "basic constraints"),
                )?;
                self.custom_constraints(
                    config,
                    layouter.namespace(|| "custom constraints"),
                    &input_note_variables,
                    &output_note_variables,
                )?;
                Ok(())
            }
        }
    };
}
