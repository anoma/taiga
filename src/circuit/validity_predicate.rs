use ark_ec::TEModelParameters;
use ark_ff::{UniformRand, Zero, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use merlin::Transcript;
use plonk_core::{
    constraint_system::StandardComposer,
    prelude::{Proof, Point},
    circuit::Circuit,
    proof_system::{pi::PublicInputs, Prover, Verifier, VerifierKey},
};
use plonk_hashing::poseidon::{constants::PoseidonConstants, poseidon::{Poseidon, NativeSpec}};
use rand::prelude::ThreadRng;
use std::marker::PhantomData;

use crate::{
    circuit::circuit_parameters::CircuitParameters, serializable_to_vec, to_embedded_field,
    HashToField,
    note::Note, poseidon::WIDTH_3,
};

pub struct ExampleValidityPredicate<'a, CP: CircuitParameters> {
    pub input_notes: &'a[Note<CP>],
    pub output_notes: &'a[Note<CP>],
    pub other_params: &'a[CP::CurveScalarField],
}

pub trait ValidityPredicate<CP: CircuitParameters> : Circuit<CP::InnerCurveScalarField, CP::InnerCurve> {
    fn new(input_notes: &[Note<CP>], output_notes: &[Note<CP>], other_params: &[CP::CurveScalarField]) -> Self;
}

impl<CP> ValidityPredicate<CP> for ExampleValidityPredicate<'_, CP>  where CP : CircuitParameters {
    fn new(input_notes: &[Note<CP>], output_notes: &[Note<CP>], other_params: &[CP::CurveScalarField]) -> Self {
        Self { input_notes, output_notes, other_params }
    }

}

pub fn field_addition_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    private_inputs: [CP::CurveScalarField;2],
    public_input: CP::CurveScalarField,
) {
    // simple circuit that checks that a + b == c
    let a = private_inputs[0];
    let b = private_inputs[1];
    let c = public_input;
    let one = <CP as CircuitParameters>::CurveScalarField::one();
    let var_a = composer.add_input(a);
    let var_b = composer.add_input(b);
    let var_zero = composer.zero_var();
    // Make first constraint a + b = c (as public input)
    composer.arithmetic_gate(|gate| {
        gate.witness(var_a, var_b, Some(var_zero))
            .add(one, one)
            .pi(-c)
    });
}


impl<CP> Circuit<CP::InnerCurveScalarField, CP::InnerCurve> for ExampleValidityPredicate<'_, CP> where CP : CircuitParameters {
    fn gadget(
            &mut self,
            composer: &mut StandardComposer<CP::InnerCurveScalarField, CP::InnerCurve>,
        ) -> Result<(), plonk_core::prelude::Error> {
        
            let cm = self.input_notes[2].commitment();
            let a = cm.x;
            let b = cm.y;
            let c = a+b;
            field_addition_gadget(composer, [a,b], c);
            Ok(())
    }
    fn padded_circuit_size(&self) -> usize {
        1 << 9
    }
}

pub struct ValidityPredicateProver<CP: CircuitParameters> {
    desc_vp: VerifierKey<CP::CurveScalarField, CP::CurvePC>, //preprocessed VP
    pub public_input: PublicInputs<CP::CurveScalarField>,
    _blind_rand: [CP::CurveScalarField; 20], //blinding randomness
    pub proof: Proof<CP::CurveScalarField, CP::CurvePC>,
    pub verifier: Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>,
    pub vk: <CP::CurvePC as PolynomialCommitment<
        CP::CurveScalarField,
        DensePolynomial<CP::CurveScalarField>,
    >>::VerifierKey,
    pub rcm_com: CP::CurveScalarField,
    pub com_vp: CP::CurveScalarField,
}

impl<CP: CircuitParameters> ValidityPredicateProver<CP> {
    pub fn precompute_prover<VP>(
        setup: &<<CP as CircuitParameters>::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        gadget: &VP,
        private_inputs: &[CP::CurveScalarField],
        public_inputs: &[CP::CurveScalarField],
    ) -> (
        Prover<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>,
        <CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::CommitterKey,
        <CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::VerifierKey,
        PublicInputs<CP::CurveScalarField>,
        VerifierKey<CP::CurveScalarField, CP::CurvePC>,
    ) 
    where VP: ValidityPredicate<CP> {
        // Create a `Prover`
        // Set the circuit using `gadget`
        // Output `prover`, `vk`, `public_input`, and `desc_vp`.

        let mut prover = Prover::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>::new(b"demo");
        prover.key_transcript(b"key", b"additional seed information");
        gadget.synthesize(prover.mut_cs(), private_inputs, public_inputs);
        let circuit_size = prover.circuit_bound().next_power_of_two();
        let (ck, vk) = CP::CurvePC::trim(setup, circuit_size, 0, None).unwrap();
        let desc_vp = prover
            .mut_cs()
            .preprocess_verifier(&ck, &mut Transcript::new(b""), PhantomData::<CP::CurvePC>)
            .unwrap();
        prover.cs.public_inputs.update_size(circuit_size);
        let pub_inp = prover.mut_cs().get_pi().clone();

        (prover, ck, vk, pub_inp, desc_vp)
    }

    pub fn precompute_verifier<VP>(
        gadget: &VP,
        private_inputs: &[CP::CurveScalarField],
        public_inputs: &[CP::CurveScalarField],
    ) -> Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC> 
    where VP : ValidityPredicate<CP>{
        let mut verifier: Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC> =
            Verifier::new(b"demo");
        verifier.key_transcript(b"key", b"additional seed information");
        gadget(verifier.mut_cs(), private_inputs, public_inputs);
        verifier
    }

    pub fn preprocess(
        prover: &mut Prover<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>,
        verifier: &mut Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>,
        ck: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::CommitterKey,
    ) {
        prover.preprocess(ck).unwrap();
        verifier.preprocess(ck).unwrap();
    }

    pub fn blinded_preprocess(
        prover: &mut Prover<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>,
        verifier: &mut Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>,
        ck: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::CommitterKey,
        rng: &mut ThreadRng,
    ) -> [CP::CurveScalarField; 20] {
        // Random F elements for blinding the circuit
        let blinding_values = [CP::CurveScalarField::rand(rng); 20];
        prover
            .preprocess_with_blinding(ck, blinding_values)
            .unwrap();
        verifier
            .preprocess_with_blinding(ck, blinding_values)
            .unwrap();
        blinding_values
    }

    pub fn new<VP>(
        setup: &<<CP as CircuitParameters>::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        gadget: &VP,
        private_inputs: &[CP::CurveScalarField],
        public_inputs: &[CP::CurveScalarField],
        blind: bool,
        rng: &mut ThreadRng,
    ) -> Self where VP: ValidityPredicate<CP> {
        // Given a gadget corresponding to a circuit, create all the computations for PBC related to the VP

        // Prover desc_vp
        let (mut prover, ck, vk, public_input, desc_vp) =
            Self::precompute_prover(setup, gadget, private_inputs, public_inputs);
        let mut verifier = Self::precompute_verifier(gadget, private_inputs, public_inputs);
        // (blinding or not) preprocessing
        let blinding_values = if blind {
            Self::blinded_preprocess(&mut prover, &mut verifier, &ck, rng)
        } else {
            Self::preprocess(&mut prover, &mut verifier, &ck);
            [CP::CurveScalarField::zero(); 20]
        };

        // proof
        let proof = prover.prove(&ck).unwrap();

        let rcm_com = CP::CurveScalarField::rand(rng);
        // cannot use `pack()` because it is implemented for a validity predicate and we only have `desc_vp`.
        let h_desc_vp = CP::CurveBaseField::hash_to_field(&serializable_to_vec(&desc_vp));
        let com_vp = CP::com_r(
            &vec![to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(h_desc_vp)],
            rcm_com,
        );

        Self {
            desc_vp,
            public_input,
            _blind_rand: blinding_values,
            proof,
            verifier,
            vk,
            rcm_com,
            com_vp,
        }
    }

    pub fn pack(&self) -> CP::CurveBaseField {
        // bits representing desc_vp
        CP::CurveBaseField::hash_to_field(&serializable_to_vec(&self.desc_vp))
    }

    pub fn commitment(&self, rand: CP::CurveScalarField) -> CP::CurveScalarField {
        // computes a commitment C = com_r(com_q(desc_vp, 0), rand)
        CP::com_r(
            &vec![to_embedded_field::<CP::CurveBaseField, CP::CurveScalarField>(self.pack())],
            rand,
        )
    }

    pub fn binding_commitment(&self) -> CP::CurveScalarField {
        // computes a commitment without randomness
        self.commitment(CP::CurveScalarField::zero())
    }

    pub fn fresh_commitment(
        &self,
        rng: &mut ThreadRng,
    ) -> (CP::CurveScalarField, CP::CurveScalarField) {
        // computes a fresh commitment C = com_r(com_q(desc_vp, 0), rand) and return (C, rand)
        let rand = CP::CurveScalarField::rand(rng);
        (self.commitment(rand), rand)
    }

    pub fn verify(&self) {
        let p_i = self.public_input.clone();
        // p_i.update_size(circuit_size);
        self.verifier.verify(&self.proof, &self.vk, &p_i).unwrap();
    }
}
