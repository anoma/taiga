use ark_ff::{BigInteger, BigInteger256, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use merlin::Transcript;
use plonk::{
    circuit::PublicInputBuilder,
    constraint_system::StandardComposer,
    prelude::Proof,
    proof_system::{Prover, Verifier, VerifierKey},
};
use rand::{prelude::ThreadRng, Rng};
use std::marker::PhantomData;

use crate::{circuit::circuit_parameters::CircuitParameters, com_p, com_q, serializable_to_vec};

pub struct ValidityPredicate<CP: CircuitParameters> {
    desc_vp: VerifierKey<CP::CurveScalarField, CP::CurvePC>, //preprocessed VP
    pub public_input: Vec<CP::CurveScalarField>,
    _blind_rand: [CP::CurveScalarField; 20], //blinding randomness
    pub proof: Proof<CP::CurveScalarField, CP::CurvePC>,
    pub verifier: Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>,
    pub vk: <CP::CurvePC as PolynomialCommitment<
        CP::CurveScalarField,
        DensePolynomial<CP::CurveScalarField>,
    >>::VerifierKey,
    pub rcm_com: BigInteger256,
    pub com_vp: CP::CurveScalarField,
}

impl<CP: CircuitParameters> ValidityPredicate<CP> {
    pub fn precompute_prover(
        setup: &<<CP as CircuitParameters>::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        gadget: fn(&mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>),
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
        Vec<CP::CurveScalarField>,
        VerifierKey<CP::CurveScalarField, CP::CurvePC>,
    ) {
        // Create a `Prover`
        // Set the circuit using `gadget`
        // Output `prover`, `vk`, `public_input`, and `desc_vp`.

        let mut prover = Prover::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>::new(b"demo");
        prover.key_transcript(b"key", b"additional seed information");
        gadget(prover.mut_cs());
        let (ck, vk) = CP::CurvePC::trim(
            setup,
            prover.circuit_size().next_power_of_two() + 6,
            0,
            None,
        )
        .unwrap();
        let desc_vp = prover
            .mut_cs()
            .preprocess_verifier(&ck, &mut Transcript::new(b""), PhantomData::<CP::CurvePC>)
            .unwrap();
        let public_input = PublicInputBuilder::new().finish(); // works only with our dummy circuit!

        (prover, ck, vk, public_input, desc_vp)
    }

    pub fn precompute_verifier(
        gadget: fn(&mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>),
    ) -> Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC> {
        let mut verifier: Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC> =
            Verifier::new(b"demo");
        verifier.key_transcript(b"key", b"additional seed information");
        gadget(verifier.mut_cs());
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

    pub fn new(
        setup: &<<CP as CircuitParameters>::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        gadget: fn(&mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>),
        blind: bool,
        rng: &mut ThreadRng,
    ) -> Self {
        // Given a gadget corresponding to a circuit, create all the computations for PBC related to the VP

        // Prover desc_vp
        let (mut prover, ck, vk, public_input, desc_vp) = Self::precompute_prover(setup, gadget);
        let mut verifier = Self::precompute_verifier(gadget);
        // (blinding or not) preprocessing
        let blinding_values;
        if blind {
            blinding_values = Self::blinded_preprocess(&mut prover, &mut verifier, &ck, rng);
        } else {
            Self::preprocess(&mut prover, &mut verifier, &ck);
            blinding_values = [CP::CurveScalarField::zero(); 20];
        }

        // proof
        let proof = prover.prove(&ck).unwrap();

        let rcm_com = rng.gen();
        // cannot use `pack()` because it is implemented for a validity predicate and we only have `desc_vp`.
        let h_desc_vp =
            com_p::<CP::CurveBaseField>(&serializable_to_vec(&desc_vp), BigInteger256::from(0));
        let com_vp = com_q::<CP::CurveScalarField>(&h_desc_vp.into_repr().to_bytes_le(), rcm_com);

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
        com_p::<CP::CurveBaseField>(&serializable_to_vec(&self.desc_vp), BigInteger256::from(0))
    }

    pub fn commitment(&self, rand: BigInteger256) -> CP::CurveScalarField {
        // computes a commitment C = com_q(com_p(desc_vp, 0), rand)
        com_q::<CP::CurveScalarField>(&self.pack().into_repr().to_bytes_le(), rand)
    }

    pub fn binding_commitment(&self) -> CP::CurveScalarField {
        // computes a commitment without randomness
        self.commitment(BigInteger256::from(0))
    }

    pub fn fresh_commitment(&self, rng: &mut ThreadRng) -> (CP::CurveScalarField, BigInteger256) {
        // computes a fresh commitment C = com_q(com_p(desc_vp, 0), rand) and return (C, rand)
        let rand: BigInteger256 = rng.gen();
        (self.commitment(rand), rand)
    }

    pub fn verify(&self) {
        self.verifier
            .verify(&self.proof, &self.vk, &self.public_input)
            .unwrap();
    }
}

pub fn send_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
) {
    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

pub fn recv_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
) {
    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

pub fn token_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
) {
    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

fn _circuit_proof<CP: CircuitParameters>() {
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(1 << 4, None, &mut rng).unwrap();

    let circuit = ValidityPredicate::<CP>::new(&pp, send_gadget::<CP>, true, &mut rng);
    circuit.verify();
}

#[test]
fn test_cirucit_proof_kzg() {
    _circuit_proof::<crate::circuit::circuit_parameters::PairingCircuitParameters>()
}
