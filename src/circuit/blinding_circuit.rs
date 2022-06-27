use std::time::Instant;

use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{
    constraint_system::StandardComposer,
    prelude::{Point, Proof},
    proof_system::{pi::PublicInputs, Prover, Verifier},
};

use crate::circuit::{
    circuit_parameters::CircuitParameters, gadgets::blinding::blinding_gadget,
    validity_predicate::ValidityPredicate,
};

pub struct BlindingCircuit<CP: CircuitParameters> {
    pub public_input: PublicInputs<CP::CurveBaseField>,
    pub proof: Proof<CP::CurveBaseField, CP::OuterCurvePC>,
    pub verifier: Verifier<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>,
    pub vk: <CP::OuterCurvePC as PolynomialCommitment<
        CP::CurveBaseField,
        DensePolynomial<CP::CurveBaseField>,
    >>::VerifierKey,
}

impl<CP: CircuitParameters> BlindingCircuit<CP> {
    pub fn precompute_prover(
        setup: &<CP::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::UniversalParams,
        gadget: fn(
            &mut StandardComposer<CP::CurveBaseField, CP::Curve>,
            private_inputs: &[CP::CurveBaseField],
            public_inputs: &[CP::CurveBaseField],
        ) -> Vec<Point<CP::Curve>>,
        private_inputs: &[CP::CurveBaseField],
        public_inputs: &[CP::CurveBaseField],
    ) -> (
        // Prover
        Prover<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>,
        // CommitterKey
        <CP::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::CommitterKey,
        // VerifierKey
        <CP::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::VerifierKey,
        // PublicInput
        PublicInputs<CP::CurveBaseField>,
    ) {
        // Create a `Prover`
        // Set the circuit using `gadget`
        // Output `prover`, `vk`, `public_input`.

        let mut prover = Prover::<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>::new(b"demo");
        prover.key_transcript(b"key", b"additional seed information");
        gadget(prover.mut_cs(), private_inputs, public_inputs);
        let (ck, vk) = CP::OuterCurvePC::trim(
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
            &mut StandardComposer<CP::CurveBaseField, CP::Curve>,
            private_inputs: &[CP::CurveBaseField],
            public_inputs: &[CP::CurveBaseField],
        ) -> Vec<Point<CP::Curve>>,
        private_inputs: &[CP::CurveBaseField],
        public_inputs: &[CP::CurveBaseField],
    ) -> Verifier<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC> {
        let mut verifier: Verifier<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC> =
            Verifier::new(b"demo");
        verifier.key_transcript(b"key", b"additional seed information");
        gadget(verifier.mut_cs(), private_inputs, public_inputs);
        verifier
    }

    pub fn preprocess(
        prover: &mut Prover<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>,
        verifier: &mut Verifier<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC>,
        ck: &<CP::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::CommitterKey,
    ) {
        prover.preprocess(ck).unwrap();
        verifier.preprocess(ck).unwrap();
    }

    pub fn new(
        setup: &<CP::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::UniversalParams,
        vp: &ValidityPredicate<CP>,
    ) -> Self {
        let (private_inputs, public_inputs) = CP::get_inputs(vp);
        // Prover desc_vp
        let (mut prover, ck, vk, public_input) = Self::precompute_prover(
            setup,
            blinding_gadget::<CP>,
            &private_inputs,
            &public_inputs,
        );
        let mut verifier =
            Self::precompute_verifier(blinding_gadget::<CP>, &private_inputs, &public_inputs);
        let t = Instant::now();
        Self::preprocess(&mut prover, &mut verifier, &ck);
        println!(
            "Time for the (prover and verifier) preprocessing: {:?}",
            t.elapsed()
        );

        // proof
        let t = Instant::now();
        let proof = prover.prove(&ck).unwrap();
        println!("Time for the blinding proof computation: {:?}", t.elapsed());

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

#[test]
fn test_vp_blind_creation() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::gadgets::field_addition::field_addition_gadget;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type InnerC = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type OuterPC = <CP as CircuitParameters>::OuterCurvePC;

    let rng = &mut rand::thread_rng();
    let setup = PC::setup(1 << 4, None, rng).unwrap();

    let (a, b, c) = (F::from(2u64), F::from(1u64), F::from(3u64));

    let vp = ValidityPredicate::<CP>::new(
        &setup,
        field_addition_gadget::<CP>,
        &[a, b],
        &[c],
        true,
        rng,
    );

    let setup_outer = OuterPC::setup(1 << 13, None, rng).unwrap();
    let blinding_vp: BlindingCircuit<CP> = BlindingCircuit::new(&setup_outer, &vp);
    blinding_vp.verify();
}
