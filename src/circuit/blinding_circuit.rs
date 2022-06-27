use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{
    constraint_system::StandardComposer,
    prelude::{Proof, Point},
    proof_system::{pi::PublicInputs, Prover, Verifier},
};

use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP};

pub struct BlindingCircuit {
    pub public_input: PublicInputs<<CP as CircuitParameters>::CurveBaseField>,
    pub proof: Proof<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::OuterCurvePC>,
    pub verifier: Verifier<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve, <CP as CircuitParameters>::OuterCurvePC>,
    pub vk: <<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
        <CP as CircuitParameters>::CurveBaseField,
        DensePolynomial<<CP as CircuitParameters>::CurveBaseField>,
    >>::VerifierKey,
}

impl BlindingCircuit {
    pub fn precompute_prover(
        setup: &<<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
            <CP as CircuitParameters>::CurveBaseField,
            DensePolynomial<<CP as CircuitParameters>::CurveBaseField>,
        >>::UniversalParams,
        gadget: fn(
            &mut StandardComposer<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve>,
            private_inputs: &[<CP as CircuitParameters>::CurveBaseField],
            public_inputs: &[<CP as CircuitParameters>::CurveBaseField],
        )->Point<<CP as CircuitParameters>::Curve>,
        private_inputs: &[<CP as CircuitParameters>::CurveBaseField],
        public_inputs: &[<CP as CircuitParameters>::CurveBaseField],
    ) -> (
        // Prover
        Prover<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve, <CP as CircuitParameters>::OuterCurvePC>,
        // CommitterKey
        <<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
            <CP as CircuitParameters>::CurveBaseField,
            DensePolynomial<<CP as CircuitParameters>::CurveBaseField>,
        >>::CommitterKey,
        // VerifierKey
        <<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
            <CP as CircuitParameters>::CurveBaseField,
            DensePolynomial<<CP as CircuitParameters>::CurveBaseField>,
        >>::VerifierKey,
        // PublicInput
        PublicInputs<<CP as CircuitParameters>::CurveBaseField>,
    ) {
        // Create a `Prover`
        // Set the circuit using `gadget`
        // Output `prover`, `vk`, `public_input`.

        let mut prover = Prover::<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve, <CP as CircuitParameters>::OuterCurvePC>::new(b"demo");
        prover.key_transcript(b"key", b"additional seed information");
        gadget(prover.mut_cs(), private_inputs, public_inputs);
        let (ck, vk) = <CP as CircuitParameters>::OuterCurvePC::trim(
            setup,
            prover.circuit_bound().next_power_of_two() + 6,
            0,
            None,
        )
        .unwrap();
        let public_input = prover.mut_cs().get_pi().clone();

        (prover, ck, vk, public_input)
    }

    pub fn precompute_verifier(
        gadget: fn(
            &mut StandardComposer<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve>,
            private_inputs: &[<CP as CircuitParameters>::CurveBaseField],
            public_inputs: &[<CP as CircuitParameters>::CurveBaseField],
        )->Point<<CP as CircuitParameters>::Curve>,
        private_inputs: &[<CP as CircuitParameters>::CurveBaseField],
        public_inputs: &[<CP as CircuitParameters>::CurveBaseField],
    ) -> Verifier<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve, <CP as CircuitParameters>::OuterCurvePC> {
        let mut verifier: Verifier<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve, <CP as CircuitParameters>::OuterCurvePC> =
            Verifier::new(b"demo");
        verifier.key_transcript(b"key", b"additional seed information");
        gadget(verifier.mut_cs(), private_inputs, public_inputs);
        verifier
    }

    pub fn preprocess(
        prover: &mut Prover<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve, <CP as CircuitParameters>::OuterCurvePC>,
        verifier: &mut Verifier<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve, <CP as CircuitParameters>::OuterCurvePC>,
        ck: &<<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
            <CP as CircuitParameters>::CurveBaseField,
            DensePolynomial<<CP as CircuitParameters>::CurveBaseField>,
        >>::CommitterKey,
    ) {
        prover.preprocess(ck).unwrap();
        verifier.preprocess(ck).unwrap();
    }

    pub fn new(
        setup: &<<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
            <CP as CircuitParameters>::CurveBaseField,
            DensePolynomial<<CP as CircuitParameters>::CurveBaseField>,
        >>::UniversalParams,
        gadget: fn(
            &mut StandardComposer<<CP as CircuitParameters>::CurveBaseField, <CP as CircuitParameters>::Curve>,
            &[<CP as CircuitParameters>::CurveBaseField],
            &[<CP as CircuitParameters>::CurveBaseField],
        )->Point<<CP as CircuitParameters>::Curve>,
        private_inputs: &[<CP as CircuitParameters>::CurveBaseField],
        public_inputs: &[<CP as CircuitParameters>::CurveBaseField],
    ) -> Self {
        // Given a gadget corresponding to a circuit, create all the computations for taiga related to the VP

        // Prover desc_vp
        let (mut prover, ck, vk, public_input) =
            Self::precompute_prover(setup, gadget, private_inputs, public_inputs);
        let mut verifier = Self::precompute_verifier(gadget, private_inputs, public_inputs);
        Self::preprocess(&mut prover, &mut verifier, &ck);

        // proof
        let proof = prover.prove(&ck).unwrap();

        Self {
            public_input,
            proof,
            verifier,
            vk,
        }
    }

    pub fn verify(&self) {
        self.verifier
            .verify(&self.proof, &self.vk, &self.public_input)
            .unwrap();
    }
}
