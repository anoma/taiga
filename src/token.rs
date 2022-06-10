use crate::circuit::{
    circuit_parameters::CircuitParameters,
    validity_predicate::{token_gadget, ValidityPredicate},
};
use ark_ff::BigInteger256;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use rand::{prelude::ThreadRng, Rng};

pub struct Token<CP: CircuitParameters> {
    name: String, // not really useful: a token will be identified with its address, defined below.
    token_vp: ValidityPredicate<CP>,
    pub rcm_addr: BigInteger256,
}

impl<CP: CircuitParameters> std::fmt::Display for Token<CP> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Token {}", self.name,)
    }
}

impl<CP: CircuitParameters> Token<CP> {
    pub fn new(
        name: &str,
        setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        rng: &mut ThreadRng,
    ) -> Self {
        let token_vp = ValidityPredicate::<CP>::new(setup, token_gadget::<CP>, false, rng);
        Self {
            name: String::from(name),
            token_vp,
            rcm_addr: rng.gen(),
        }
    }

    pub fn address(&self) -> CP::CurveScalarField {
        // The token address is a binding commitment of the token VP. TODO add name for unicity?
        self.token_vp.commitment(self.rcm_addr)
    }

    pub fn get_vp(&self) -> &ValidityPredicate<CP> {
        &self.token_vp
    }
}
