use ark_ff::{BigInteger, BigInteger256, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use merlin::Transcript;
use plonk_core::{
    circuit::Circuit,
    constraint_system::StandardComposer,
    prelude::Proof,
    proof_system::{pi::PublicInputs, Prover, Verifier, VerifierKey},
};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, PlonkSpec, Poseidon},
};
use rand::{prelude::ThreadRng, thread_rng, Rng};
use std::marker::PhantomData;

use crate::{
    circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters as CP},
    poseidon::WIDTH_3,
    serializable_to_vec,
};

pub struct ValidityPredicate<CP: CircuitParameters> {
    desc_vp: VerifierKey<CP::CurveScalarField, CP::CurvePC>, //preprocessed VP
    pub public_input: PublicInputs<CP::CurveScalarField>,
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
        gadget: fn(
            &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
            private_inputs: &Vec<CP::CurveScalarField>,
            public_inputs: &Vec<CP::CurveScalarField>,
        ),
        private_inputs: &Vec<CP::CurveScalarField>,
        public_inputs: &Vec<CP::CurveScalarField>,
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
    ) {
        // Create a `Prover`
        // Set the circuit using `gadget`
        // Output `prover`, `vk`, `public_input`, and `desc_vp`.

        let mut prover = Prover::<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC>::new(b"demo");
        prover.key_transcript(b"key", b"additional seed information");
        gadget(prover.mut_cs(), private_inputs, public_inputs);
        let (ck, vk) = CP::CurvePC::trim(
            setup,
            prover.circuit_bound().next_power_of_two() + 6,
            0,
            None,
        )
        .unwrap();
        let desc_vp = prover
            .mut_cs()
            .preprocess_verifier(&ck, &mut Transcript::new(b""), PhantomData::<CP::CurvePC>)
            .unwrap();
        let public_input = prover.mut_cs().get_pi().clone();

        (prover, ck, vk, public_input, desc_vp)
    }

    pub fn precompute_verifier(
        gadget: fn(
            &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
            private_inputs: &Vec<CP::CurveScalarField>,
            public_inputs: &Vec<CP::CurveScalarField>,
        ),
        public_inputs: &Vec<CP::CurveScalarField>,
    ) -> Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC> {
        let mut verifier: Verifier<CP::CurveScalarField, CP::InnerCurve, CP::CurvePC> =
            Verifier::new(b"demo");
        verifier.key_transcript(b"key", b"additional seed information");
        gadget(verifier.mut_cs(), &vec![], public_inputs);
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
        gadget: fn(
            &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
            &Vec<CP::CurveScalarField>,
            &Vec<CP::CurveScalarField>,
        ),
        private_inputs: &Vec<CP::CurveScalarField>,
        public_inputs: &Vec<CP::CurveScalarField>,
        blind: bool,
        rng: &mut ThreadRng,
    ) -> Self {
        // Given a gadget corresponding to a circuit, create all the computations for PBC related to the VP

        // Prover desc_vp
        let (mut prover, ck, vk, public_input, desc_vp) =
            Self::precompute_prover(setup, gadget, private_inputs, public_inputs);
        let mut verifier = Self::precompute_verifier(gadget, public_inputs);
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
        let h_desc_vp = CP::com_p(&serializable_to_vec(&desc_vp), BigInteger256::from(0));
        let com_vp = CP::com_q(&h_desc_vp.into_repr().to_bytes_le(), rcm_com);

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
        CP::com_p(&serializable_to_vec(&self.desc_vp), BigInteger256::from(0))
    }

    pub fn commitment(&self, rand: BigInteger256) -> CP::CurveScalarField {
        // computes a commitment C = com_q(com_p(desc_vp, 0), rand)
        CP::com_q(&self.pack().into_repr().to_bytes_le(), rand)
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

pub fn trivial_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    _private_inputs: &Vec<CP::CurveScalarField>,
    _public_inputs: &Vec<CP::CurveScalarField>,
) {
    // no input in this trivial gadget...

    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

pub fn poseidon_hash_curve_scalar_field_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    private_inputs: &Vec<CP::CurveScalarField>,
    public_inputs: &Vec<CP::CurveScalarField>,
) {
    // private_inputs are the inputs for the Poseidon hash (?)
    let hash_output = public_inputs[0];

    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();

    // inputs in the circuit
    let inputs_var = private_inputs
        .iter()
        .map(|x| composer.add_input(*x))
        .collect::<Vec<_>>();
    // hash circuit
    let mut poseidon_circuit = Poseidon::<_, PlonkSpec<WIDTH_3>, WIDTH_3>::new(
        composer,
        &poseidon_hash_param_bls12_377_scalar_arity2,
    );
    inputs_var.iter().for_each(|x| {
        poseidon_circuit.input(*x).unwrap();
    });
    let plonk_hash = poseidon_circuit.output_hash(composer);

    composer.check_circuit_satisfied();

    let expected = composer.add_input(hash_output);
    composer.assert_equal(expected, plonk_hash);

    composer.check_circuit_satisfied();
}

pub fn signature_verification_send_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    _private_inputs: &Vec<CP::CurveScalarField>,
    _public_inputs: &Vec<CP::CurveScalarField>,
) {
    // todo implement the circuit
    // this circuit check a signature
    // it involves scalar multiplication circuits if we use ECDSA
    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

pub fn black_list_recv_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    _private_inputs: &Vec<CP::CurveScalarField>,
    _public_inputs: &Vec<CP::CurveScalarField>,
) {
    // todo implement the circuit
    // this circuit check that the sent note user address is not in a given list
    //
    // public input:
    // * a commitment `c` to the sent note
    // * a list `blacklist` of unauthorized people
    // private input:
    // * the entire note `n`
    // * the random value `r` used for the note commitment
    //
    // circuit:
    // check that `Com(n, r) == c` and that `n.owner_address not in blacklist`.

    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

pub fn upper_bound_token_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    _private_inputs: &Vec<CP::CurveScalarField>,
    _public_inputs: &Vec<CP::CurveScalarField>,
) {
    // todo implement the circuit
    // this circuit check that the transaction involving the token is bounded by a given value
    // it corresponds to a range check in terms of circuits
    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| {
        gate.witness(var_one, var_one, None)
            .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
    });
}

pub fn another_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    private_inputs: &Vec<CP::CurveScalarField>,
    public_inputs: &Vec<CP::CurveScalarField>,
) {
    let (a, b) = if private_inputs.len() == 0 {
        (CP::CurveScalarField::zero(), CP::CurveScalarField::zero())
    } else {
        (private_inputs[0], private_inputs[1])
    };
    let c = public_inputs[0];

    let one = <CP as CircuitParameters>::CurveScalarField::one();

    let var_a = composer.add_input(a);
    let var_b = composer.add_input(b);
    let var_zero = composer.zero_var();

    // Make first constraint a + b = c (as public input)
    composer.arithmetic_gate(|gate| {
        gate.witness(var_a, var_b, Some(var_zero))
            .add(<CP as CircuitParameters>::CurveScalarField::one(), one)
            .pi(-c)
    });

    let var_one = composer.add_input(CP::CurveScalarField::one());
    composer.arithmetic_gate(|gate| gate.witness(var_one, var_one, None).add(one, one));
}

fn vp_proof_verify<CP: CircuitParameters>(
    gadget: fn(
        &mut StandardComposer<
            <CP as CircuitParameters>::CurveScalarField,
            <CP as CircuitParameters>::InnerCurve,
        >,
        &Vec<CP::CurveScalarField>,
        &Vec<CP::CurveScalarField>,
    ),
    private_inputs: &Vec<CP::CurveScalarField>,
    public_inputs: &Vec<CP::CurveScalarField>,
) {
    let mut rng = ThreadRng::default();
    let pp = <CP as CircuitParameters>::CurvePC::setup(2 * 300, None, &mut rng).unwrap();

    let circuit =
        ValidityPredicate::<CP>::new(&pp, gadget, private_inputs, public_inputs, true, &mut rng);
    circuit.verify();
}

#[test]
fn test_trivial_gadget() {
    vp_proof_verify::<CP>(
        trivial_gadget::<CP>,
        &vec![],
        &vec![<CP as CircuitParameters>::CurveScalarField::zero()],
    );
}

#[test]
fn test_another_gadget() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    let a = <CP as CircuitParameters>::CurveScalarField::from(2u64);
    let b = <CP as CircuitParameters>::CurveScalarField::from(1u64);
    let c = <CP as CircuitParameters>::CurveScalarField::from(3u64);
    vp_proof_verify::<CP>(another_gadget::<CP>, &vec![a, b], &vec![c]);
}

#[test]
fn test_signature_verification_send_gadget() {
    vp_proof_verify::<CP>(
        signature_verification_send_gadget::<CP>,
        &vec![],
        &vec![<CP as CircuitParameters>::CurveScalarField::zero()],
    );
}
#[test]
fn test_poseidon_gadget() {
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;

    let mut rng = thread_rng();
    let inputs = (0..(WIDTH_3 - 1))
        .map(|_| <CP as CircuitParameters>::CurveScalarField::rand(&mut rng))
        .collect::<Vec<_>>();
    let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();

    let mut poseidon = Poseidon::<
        (),
        NativeSpec<<CP as CircuitParameters>::CurveScalarField, WIDTH_3>,
        WIDTH_3,
    >::new(&mut (), &poseidon_hash_param_bls12_377_scalar_arity2);

    inputs.iter().for_each(|x| {
        poseidon.input(*x).unwrap();
    });
    let output = poseidon.output_hash(&mut ());

    vp_proof_verify::<CP>(
        poseidon_hash_curve_scalar_field_gadget::<CP>,
        &inputs,
        &vec![output],
    );
}

// // todo we need to add some private and public inputs for the gadget adding in the VP !
// #[test]
// fn test_poseidon_hash_curve_scalar_field_gadget() {
//     use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
//     // we try to compute a circuit and proof+verify.
//     let mut rng = ThreadRng::default();
//     let pp = <CP as CircuitParameters>::CurvePC::setup(2 * 300, None, &mut rng).unwrap();

//     let mut prover: Prover<
//         <CP as CircuitParameters>::CurveScalarField,
//         <CP as CircuitParameters>::InnerCurve,
//         <CP as CircuitParameters>::CurvePC,
//     > = Prover::new(b"demo");

//     let inputs = (0..(WIDTH_3 - 1))
//         .map(|_| <CP as CircuitParameters>::CurveScalarField::rand(&mut rng))
//         .collect::<Vec<_>>();
//     let poseidon_hash_param_bls12_377_scalar_arity2 = PoseidonConstants::generate::<WIDTH_3>();

//     let mut poseidon = Poseidon::<
//         (),
//         NativeSpec<<CP as CircuitParameters>::CurveScalarField, WIDTH_3>,
//         WIDTH_3,
//     >::new(&mut (), &poseidon_hash_param_bls12_377_scalar_arity2);

//     inputs.iter().for_each(|x| {
//         poseidon.input(*x).unwrap();
//     });
//     let output = poseidon.output_hash(&mut ());

//     poseidon_hash_curve_scalar_field_gadget::<CP>(prover.mut_cs(), &inputs, output);
//     let (ck, vk) = <CP as CircuitParameters>::CurvePC::trim(&pp, 2 * 300, 0, None).unwrap();
//     let mut rng = ark_std::test_rng();
//     let blinding_values = [<CP as CircuitParameters>::CurveScalarField::rand(&mut rng); 20];
//     prover
//         .preprocess_with_blinding(&ck, blinding_values)
//         .unwrap();
//     let public_inputs = prover.mut_cs().get_pi().clone();
//     let proof = prover.prove(&ck).unwrap();
//     let mut verifier = Verifier::<
//         <CP as CircuitParameters>::CurveScalarField,
//         <CP as CircuitParameters>::InnerCurve,
//         <CP as CircuitParameters>::CurvePC,
//     >::new(b"demo");
//     poseidon_hash_curve_scalar_field_gadget::<CP>(verifier.mut_cs(), &inputs, output);
//     verifier
//         .preprocess_with_blinding(&ck, blinding_values)
//         .unwrap();
//     assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());
// }

#[test]
fn test_black_list_recv_gadget() {
    vp_proof_verify::<CP>(
        black_list_recv_gadget::<CP>,
        &vec![],
        &vec![<CP as CircuitParameters>::CurveScalarField::zero()],
    );
}

#[test]
fn test_upper_bound_token_gadget() {
    vp_proof_verify::<CP>(
        upper_bound_token_gadget::<CP>,
        &vec![],
        &vec![<CP as CircuitParameters>::CurveScalarField::zero()],
    );
}
