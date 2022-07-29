pub const NUM_NOTE: usize = 4;
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::integrity::{
    input_note_constraint, output_note_constraint, ValidityPredicateInputNoteVariables,
    ValidityPredicateOuputNoteVariables,
};
use crate::note::{Note, NoteCommitment};
use crate::nullifier::Nullifier;
use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{
    //circuit::Circuit,
    constraint_system::StandardComposer,
    error::to_pc_error,
    //prelude::Error,
    proof_system::{verifier::Verifier, VerifierKey},
};

use pasta_curves::vesta;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use plonk_hashing::poseidon::poseidon::Poseidon;

use halo2_gadgets::poseidon::Pow5Config;

#[derive(Clone, Debug)]
struct VPConfig {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; 2],

    /// This is the public input (instance) column.
    instance: Column<Instance>,

    // We need a selector to enable the multiplication gate, so that we aren't placing
    // any constraints on cells where `NumericInstructions::mul` is not being used.
    // This is important when building larger circuits, where columns are used by
    // multiple sets of instructions.
    s_mul: Selector,

    poseidon: Pow5Config<vesta::Scalar, 3, 2>,
}

pub trait ValidityPredicate :
    Circuit<vesta::Scalar>
{

    // Default implementation, constrains the notes integrity and outputs variables of notes.
    fn basic_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<vesta::Scalar>,
    ) -> Result<
        (
            Vec<ValidityPredicateInputNoteVariables>,
            Vec<ValidityPredicateOuputNoteVariables>,
        ),
        Error,
    > {
        let input_notes = self.get_input_notes();
        let output_notes = self.get_output_notes();
        let mut input_note_variables = vec![];
        let mut output_note_variables = vec![];
        /*for i in 0..NUM_NOTE {
            let input_note_var = input_note_constraint(&input_notes[i], composer)?;
            let output_note_var =
                output_note_constraint(&output_notes[i], &input_note_var.nf, composer)?;
            input_note_variables.push(input_note_var);
            output_note_variables.push(output_note_var);
        }*/
        Ok((input_note_variables, output_note_variables))
    }

    /*fn get_desc_vp(
        &mut self,
        vp_setup: &<CP::CurvePC as PolynomialCommitment<
            vesta::Scalar,
            DensePolynomial<vesta::Scalar>,
        >>::UniversalParams,
    ) -> Result<VerifierKey<vesta::Scalar, CP::CurvePC>, Error> {
        let (ck, _) = CP::CurvePC::trim(vp_setup, self.padded_circuit_size(), 0, None)
            .map_err(to_pc_error::<vesta::Scalar, CP::CurvePC>)?;
        let mut verifier = Verifier::new(b"CircuitCompilation");
        self.gadget(verifier.mut_cs())?;
        verifier
            .cs
            .public_inputs
            .update_size(verifier.circuit_bound());
        verifier.preprocess(&ck)?;
        Ok(verifier
            .verifier_key
            .expect("Unexpected error. Missing VerifierKey in compilation"))
    }*/

    // VP designer should implement the following functions.
    //fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE];
    //fn get_output_notes(&self) -> &[Note<CP>; NUM_NOTE];
    fn custom_constraints<L>(
        &self,
        config: Self::Config,
        layouter: impl Layouter<vesta::Scalar>,
                input_note_variables: &[ValidityPredicateInputNoteVariables],
        output_note_variables: &[ValidityPredicateOuputNoteVariables],
    ) -> Result<(), Error>;
}


impl<VP> Circuit<vesta::Scalar> for VP where VP : ValidityPredicate {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = VPConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<vesta::Scalar>,
    ) -> Result<(), Error> {
        let (input_note_variables, output_note_variables) = self.basic_constraints(config, layouter)?;
        self.custom_constraints(config, layouter, &input_note_variables, &output_note_variables)
    }

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<vesta::Scalar>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        let advice = [meta.advice_column(), meta.advice_column()];

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

        // Create a fixed column to load constants.
        let constant = meta.fixed_column();

        //FieldChip::configure(meta, advice, instance, constant)
    }
}

