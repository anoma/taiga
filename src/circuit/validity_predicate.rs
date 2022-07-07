pub const NUM_NOTE: usize = 4;
use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::integrity::{
    input_note_constraint, output_note_constraint, ValidityPredicateInputNoteVariables,
    ValidityPredicateOuputNoteVariables,
};
use crate::note::Note;
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};

pub trait ValidityPredicate<CP: CircuitParameters>:
    Circuit<CP::CurveScalarField, CP::InnerCurve>
{
    // Default implementation, used in gadgets function in Circuit trait.
    fn gadget_vp(
        &mut self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<(), Error> {
        let (input_note_variables, output_note_variables) = self.basic_constraints(composer)?;
        self.custom_constraints(composer, &input_note_variables, &output_note_variables)
    }

    // Default implementation, constrains the notes integrity and outputs variables of notes.
    fn basic_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    ) -> Result<
        (
            Vec<ValidityPredicateInputNoteVariables>,
            Vec<ValidityPredicateOuputNoteVariables>,
        ),
        Error,
    > {
        let input_notes = self.get_input_notes();
        let output_notes = self.output_notes();
        let mut input_note_variables = vec![];
        let mut output_note_variables = vec![];
        for i in 0..NUM_NOTE {
            let input_note_var = input_note_constraint(&input_notes[i], composer)?;
            let output_note_var =
                output_note_constraint(&output_notes[i], &input_note_var.nf, composer)?;
            input_note_variables.push(input_note_var);
            output_note_variables.push(output_note_var);
        }
        Ok((input_note_variables, output_note_variables))
    }

    // VP designer should implement the following functions.
    fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE];
    fn output_notes(&self) -> &[Note<CP>; NUM_NOTE];
    fn custom_constraints(
        &self,
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        input_note_variables: &[ValidityPredicateInputNoteVariables],
        output_note_variables: &[ValidityPredicateOuputNoteVariables],
    ) -> Result<(), Error>;
}

mod test {
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::gadgets::field_addition::field_addition_gadget;
    use crate::circuit::integrity::{
        ValidityPredicateInputNoteVariables, ValidityPredicateOuputNoteVariables,
    };
    use crate::circuit::validity_predicate::{ValidityPredicate, NUM_NOTE};
    use crate::note::Note;
    use ark_ff::One;
    use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, prelude::Error};

    // ExampleValidityPredicate have a custom constraint with a + b = c,
    // in which a, b are private inputs and c is a public input.
    pub struct ExampleValidityPredicate<CP: CircuitParameters> {
        // basic "private" inputs to the VP
        pub input_notes: [Note<CP>; NUM_NOTE],
        pub output_notes: [Note<CP>; NUM_NOTE],
        // custom "private" inputs to the VP
        pub a: CP::CurveScalarField,
        pub b: CP::CurveScalarField,
        // custom "public" inputs to the VP
        pub c: CP::CurveScalarField,
    }

    impl<CP> ValidityPredicate<CP> for ExampleValidityPredicate<CP>
    where
        CP: CircuitParameters,
    {
        fn get_input_notes(&self) -> &[Note<CP>; NUM_NOTE] {
            &self.input_notes
        }

        fn output_notes(&self) -> &[Note<CP>; NUM_NOTE] {
            &self.output_notes
        }

        fn custom_constraints(
            &self,
            composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
            _input_note_variables: &[ValidityPredicateInputNoteVariables],
            _output_note_variables: &[ValidityPredicateOuputNoteVariables],
        ) -> Result<(), Error> {
            let var_a = composer.add_input(self.a);
            let var_b = composer.add_input(self.b);
            let var_zero = composer.zero_var();

            field_addition_gadget::<CP>(composer, var_a, var_b, self.c);

            let one = <CP as CircuitParameters>::CurveScalarField::one();
            // Make first constraint a + b = c (as public input)
            composer.arithmetic_gate(|gate| {
                gate.witness(var_a, var_b, Some(var_zero))
                    .add(one, one)
                    .pi(-self.c)
            });
            Ok(())
        }
    }

    impl<CP> Circuit<CP::CurveScalarField, CP::InnerCurve> for ExampleValidityPredicate<CP>
    where
        CP: CircuitParameters,
    {
        const CIRCUIT_ID: [u8; 32] = [0x00; 32];

        // Default implementation
        fn gadget(
            &mut self,
            composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        ) -> Result<(), Error> {
            self.gadget_vp(composer)
        }

        fn padded_circuit_size(&self) -> usize {
            1 << 17
        }
    }

    #[test]
    fn test_vp_example() {
        use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
        type Fr = <CP as CircuitParameters>::CurveScalarField;
        type P = <CP as CircuitParameters>::InnerCurve;
        type PC = <CP as CircuitParameters>::CurvePC;
        use ark_poly_commit::PolynomialCommitment;
        use ark_std::{test_rng, UniformRand};
        use plonk_core::circuit::{verify_proof, VerifierData};

        let mut rng = test_rng();
        let input_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
        let output_notes = [(); NUM_NOTE].map(|_| Note::<CP>::dummy(&mut rng));
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a + b;
        let mut example_vp = ExampleValidityPredicate {
            input_notes,
            output_notes,
            a,
            b,
            c,
        };

        // Generate CRS
        let pp = PC::setup(example_vp.padded_circuit_size(), None, &mut rng).unwrap();

        // Compile the circuit
        let (pk_p, vk) = example_vp.compile::<PC>(&pp).unwrap();

        // Prover
        let (proof, pi) = example_vp.gen_proof::<PC>(&pp, pk_p, b"Test").unwrap();

        // Verifier
        let verifier_data = VerifierData::new(vk, pi);
        verify_proof::<Fr, P, PC>(&pp, verifier_data.key, &proof, &verifier_data.pi, b"Test")
            .unwrap();
    }
}
