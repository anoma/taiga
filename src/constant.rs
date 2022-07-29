use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use lazy_static::lazy_static;
use plonk_core::commitment::KZG10;
use rand_core::OsRng;
use std::collections::HashMap;

pub const CIRCUIT_SIZE_2_15: usize = 1 << 15;
pub const CIRCUIT_SIZE_2_16: usize = 1 << 16;
pub const CIRCUIT_SIZE_2_17: usize = 1 << 17;
pub const BLINDING_CIRCUIT_SIZE: usize = CIRCUIT_SIZE_2_15;
pub const ACTION_CIRCUIT_SIZE: usize = CIRCUIT_SIZE_2_15;
pub const ACTION_PUBLIC_INPUT_NF_INDEX: usize = 10781;
pub const ACTION_PUBLIC_INPUT_ROOT_INDEX: usize = 12530;
pub const ACTION_PUBLIC_INPUT_CM_INDEX: usize = 19586;

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
                KZG10::<ark_bls12_381_new::Bls12_381New>::setup(*circuit_size, None, &mut OsRng).unwrap();
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
        // for circuit_size in &[CIRCUIT_SIZE_2_15] {
            let setup =
                KZG10::<ark_bw6_764_new::BW6_764New>::setup(CIRCUIT_SIZE_2_15, None, &mut OsRng).unwrap();
            m.insert(CIRCUIT_SIZE_2_15, setup);
        // }
        m
    };
}
