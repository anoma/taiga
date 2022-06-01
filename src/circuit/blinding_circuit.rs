use ark_ff::One;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{
    constraint_system::StandardComposer,
    prelude::Proof,
    proof_system::{pi::PublicInputs, Prover, Verifier},
};

use crate::circuit::circuit_parameters::CircuitParameters;

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
        setup: &<<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::UniversalParams,
        gadget: fn(&mut StandardComposer<CP::CurveBaseField, CP::Curve>),
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
        gadget(prover.mut_cs());
        let (ck, vk) = CP::OuterCurvePC::trim(
            setup,
            prover.circuit_bound().next_power_of_two() + 6,
            0,
            None,
        )
        .unwrap();
        let public_input = PublicInputs::new(4); // works only with our dummy circuit!

        (prover, ck, vk, public_input)
    }

    pub fn precompute_verifier(
        gadget: fn(&mut StandardComposer<CP::CurveBaseField, CP::Curve>),
    ) -> Verifier<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC> {
        let mut verifier: Verifier<CP::CurveBaseField, CP::Curve, CP::OuterCurvePC> =
            Verifier::new(b"demo");
        verifier.key_transcript(b"key", b"additional seed information");
        gadget(verifier.mut_cs());
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
        setup: &<<CP as CircuitParameters>::OuterCurvePC as PolynomialCommitment<
            CP::CurveBaseField,
            DensePolynomial<CP::CurveBaseField>,
        >>::UniversalParams,
        gadget: fn(&mut StandardComposer<CP::CurveBaseField, CP::Curve>),
    ) -> Self {
        // Given a gadget corresponding to a circuit, create all the computations for PBC related to the VP

        // Prover desc_vp
        let (mut prover, ck, vk, public_input) = Self::precompute_prover(setup, gadget);
        let mut verifier = Self::precompute_verifier(gadget);
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

pub fn blind_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveBaseField, CP::Curve>,
) {
    // this one could be hard-coded here (not customizable)
    let var_one = composer.add_input(CP::CurveBaseField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveBaseField::one(), CP::CurveBaseField::one())
    });
}

fn _blinding_circuit_proof<CP: CircuitParameters>() {
    use rand::rngs::ThreadRng;
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::OuterCurvePC::setup(1 << 4, None, &mut rng).unwrap();

    let circuit = BlindingCircuit::<CP>::new(&pp, blind_gadget::<CP>);
    circuit.verify();
}

#[test]
fn test_blinding_cirucit_proof_kzg() {
    _blinding_circuit_proof::<crate::circuit::circuit_parameters::PairingCircuitParameters>()
}
