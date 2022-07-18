use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::validity_predicate::ValidityPredicate;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{
    circuit::Circuit,
    constraint_system::StandardComposer,
    error::to_pc_error,
    prelude::{Error, Point},
    proof_system::{verifier::Verifier, Blinding, VerifierKey},
};
use rand::RngCore;

pub struct BlindingCircuit<CP: CircuitParameters> {
    pub vk: VerifierKey<CP::CurveScalarField, CP::CurvePC>,
    pub blinding: Blinding<CP::CurveScalarField>,
    pub zh: [CP::CurveBaseField; 2],
    pub private_inputs: Vec<CP::CurveBaseField>,
}

impl<CP> Circuit<CP::CurveBaseField, CP::Curve> for BlindingCircuit<CP>
where
    CP: CircuitParameters,
{
    const CIRCUIT_ID: [u8; 32] = [0x01; 32];

    // Default implementation
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<CP::CurveBaseField, CP::Curve>,
    ) -> Result<(), Error> {
        // parse the public inputs (todo is Com(Z_H) a public input?)
        let com_z_h = TEGroupAffine::<CP::Curve>::new(self.zh[0], self.zh[1]);

        assert_eq!(self.private_inputs.len() % 3, 0);
        let mut i = 0;
        let mut q: Point<CP::Curve>;
        while i < self.private_inputs.len() {
            // parse the private inputs
            q = composer.add_affine(TEGroupAffine::<CP::Curve>::new(
                self.private_inputs[i],
                self.private_inputs[i + 1],
            ));
            let b = composer.add_input(self.private_inputs[i + 2]);
            // constraints
            let b_zh = composer.fixed_base_scalar_mul(b, com_z_h);
            let b_zh_add_q = composer.point_addition_gate(q, b_zh);

            // public blinded point
            composer.public_inputize(b_zh_add_q.x());
            composer.public_inputize(b_zh_add_q.y());

            i += 3;
        }

        println!("circuit size: {}", composer.circuit_bound());
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 12
    }
}

impl<CP: CircuitParameters> BlindingCircuit<CP> {
    pub fn new<VP>(
        rng: &mut impl RngCore,
        vp: &mut VP,
        vp_setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
    ) -> Result<Self, Error>
    where
        VP: ValidityPredicate<CP>,
    {
        let blinding = Blinding::<CP::CurveScalarField>::rand(rng);
        let vp_circuit_size = vp.padded_circuit_size();
        let (ck, _) = CP::CurvePC::trim(vp_setup, vp_circuit_size, 0, None)
            .map_err(to_pc_error::<CP::CurveScalarField, CP::CurvePC>)?;
        let mut verifier = Verifier::new(b"CircuitCompilation");
        vp.gadget(verifier.mut_cs())?;
        verifier
            .cs
            .public_inputs
            .update_size(verifier.circuit_bound());
        verifier.preprocess(&ck)?;
        let vk = verifier
            .verifier_key
            .expect("Unexpected error. Missing VerifierKey in compilation");
        let (private_inputs, zh) = CP::get_inputs(&vk, &ck, &blinding);

        Ok(Self {
            vk,
            blinding,
            zh,
            private_inputs,
        })
    }
}
