use crate::action::ActionInfo;
use crate::circuit::blinding_circuit::BlindingCircuit;
use crate::circuit::circuit_parameters::PairingCircuitParameters;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use lazy_static::lazy_static;
use plonk_core::circuit::Circuit;
use plonk_core::commitment::KZG10;
use plonk_core::proof_system::{ProverKey, VerifierKey};
use rand_core::OsRng;
use std::collections::HashMap;

pub const CIRCUIT_SIZE_2_13: usize = 1 << 13;
pub const CIRCUIT_SIZE_2_15: usize = 1 << 15;
pub const CIRCUIT_SIZE_2_16: usize = 1 << 16;
pub const CIRCUIT_SIZE_2_17: usize = 1 << 17;
pub const BLINDING_CIRCUIT_SIZE: usize = CIRCUIT_SIZE_2_13;
pub const ACTION_CIRCUIT_SIZE: usize = CIRCUIT_SIZE_2_15;
pub const ACTION_PUBLIC_INPUT_NF_INDEX: usize = 10781;
pub const ACTION_PUBLIC_INPUT_ROOT_INDEX: usize = 12530;
pub const ACTION_PUBLIC_INPUT_CM_INDEX: usize = 19586;
pub const BLIND_ELEMENTS_NUM: usize = 6;

lazy_static! {
    pub static ref PC_SETUP_MAP: HashMap<
        usize,
        <KZG10<ark_bls12_381_new::Bls12_381New> as PolynomialCommitment<
            ark_bls12_381_new::Fr,
            DensePolynomial<ark_bls12_381_new::Fr>,
        >>::UniversalParams,
    > = {
        let mut m = HashMap::new();
        for circuit_size in &[CIRCUIT_SIZE_2_15, CIRCUIT_SIZE_2_16, CIRCUIT_SIZE_2_17] {
            let setup =
                KZG10::<ark_bls12_381_new::Bls12_381New>::setup(*circuit_size, None, &mut OsRng)
                    .unwrap();
            m.insert(*circuit_size, setup);
        }
        m
    };
}

lazy_static! {
    pub static ref OPC_SETUP_MAP: HashMap<
        usize,
        <KZG10<ark_bw6_764_new::BW6_764New> as PolynomialCommitment<
            ark_bw6_764_new::Fr,
            DensePolynomial<ark_bw6_764_new::Fr>,
        >>::UniversalParams,
    > = {
        let mut m = HashMap::new();
        // for circuit_size in &[CIRCUIT_SIZE_2_13] {
            let setup =
                KZG10::<ark_bw6_764_new::BW6_764New>::setup(CIRCUIT_SIZE_2_13, None, &mut OsRng).unwrap();
            m.insert(CIRCUIT_SIZE_2_13, setup);
        // }
        m
    };
}

lazy_static! {
    pub static ref ACTION_KEY: (ProverKey<ark_bls12_381_new::Fr>, VerifierKey<ark_bls12_381_new::Fr, KZG10<ark_bls12_381_new::Bls12_381New>>) = {
        let action_info = ActionInfo::<PairingCircuitParameters>::dummy(&mut OsRng);
        let (_action, mut action_circuit) = action_info.build(&mut OsRng).unwrap();

        // Generate CRS
        let pp = PC_SETUP_MAP.get(&ACTION_CIRCUIT_SIZE).unwrap();

        // Compile the circuit
        action_circuit.compile::<KZG10<ark_bls12_381_new::Bls12_381New>>(pp).unwrap()
    };
}

lazy_static! {
    pub static ref BLIND_VP_KEY: (ProverKey<ark_bls12_381_new::Fq>, VerifierKey<ark_bls12_381_new::Fq, KZG10<ark_bw6_764_new::BW6_764New>>) = {
        let mut blinding_circuit = BlindingCircuit::<PairingCircuitParameters>::dummy(&mut OsRng);

        // Generate CRS
        let pp = OPC_SETUP_MAP.get(&BLINDING_CIRCUIT_SIZE).unwrap();

        // Compile the circuit
        blinding_circuit.compile::<KZG10<ark_bw6_764_new::BW6_764New>>(pp).unwrap()
    };
}
