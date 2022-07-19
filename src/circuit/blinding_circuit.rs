use crate::circuit::circuit_parameters::CircuitParameters;
use crate::poseidon::WIDTH_9;
use crate::vp_description::ValidityPredicateDescription;
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use ark_ff::UniformRand;
use ark_ff::{BigInteger, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{
    circuit::Circuit, constraint_system::StandardComposer, prelude::Error, prelude::Variable,
    proof_system::Blinding,
};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{PlonkSpec, Poseidon},
};
use rand::RngCore;
const BLINDING_PC_NUM: usize = 6;

pub struct BlindingCircuit<CP: CircuitParameters> {
    pub vp_desc: ValidityPredicateDescription<CP>,
    pub blinding: Blinding<CP::CurveScalarField>,
    pub zh: [CP::CurveBaseField; 2],
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

        let blind_vec = vec![
            self.blinding.q_m,
            self.blinding.q_l,
            self.blinding.q_r,
            self.blinding.q_o,
            self.blinding.q_4,
            self.blinding.q_c,
        ];
        assert_eq!(blind_vec.len(), BLINDING_PC_NUM);
        let vp_desc = self.vp_desc.get_pack().unwrap();

        // Constrain vp blinding
        for (point, blind) in vp_desc[0..2 * BLINDING_PC_NUM]
            .chunks(2)
            .zip(blind_vec.iter())
        {
            let q = composer.add_affine(TEGroupAffine::<CP::Curve>::new(point[0], point[1]));
            let blind_convert =
                CP::CurveBaseField::from_le_bytes_mod_order(&blind.into_repr().to_bytes_le());
            let b = composer.add_input(blind_convert);
            let b_zh = composer.fixed_base_scalar_mul(b, com_z_h);
            let b_zh_add_q = composer.point_addition_gate(q, b_zh);

            // public blinded point
            composer.public_inputize(b_zh_add_q.x());
            composer.public_inputize(b_zh_add_q.y());
        }

        // Constrain Com_q(vp_desc)
        let poseidon_param_9: PoseidonConstants<CP::CurveBaseField> =
            PoseidonConstants::generate::<WIDTH_9>();
        let mut poseidon_circuit =
            Poseidon::<_, PlonkSpec<WIDTH_9>, WIDTH_9>::new(composer, &poseidon_param_9);

        let hash_vec = vp_desc
            .chunks_exact(8)
            .map(|chunk| {
                poseidon_circuit.reset(composer);
                for x in chunk.iter() {
                    let var = composer.add_input(*x);
                    poseidon_circuit.input(var).unwrap();
                }
                poseidon_circuit.output_hash(composer)
            })
            .collect::<Vec<Variable>>();

        poseidon_circuit.reset(composer);
        for v in hash_vec.iter() {
            poseidon_circuit.input(*v).unwrap();
        }
        let compressed_vp_desc = poseidon_circuit.output_hash(composer);

        // public compressed_vp_desc for test, remove it when implemented com_vp.
        composer.public_inputize(&compressed_vp_desc);

        // TODO: Constrain com_vp

        println!("circuit size: {}", composer.circuit_bound());
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 15
    }
}

impl<CP: CircuitParameters> BlindingCircuit<CP> {
    pub fn new(
        rng: &mut impl RngCore,
        vp_desc: ValidityPredicateDescription<CP>,
        vp_setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
        vp_circuit_size: usize,
    ) -> Result<Self, Error> {
        let blinding = Blinding::<CP::CurveScalarField>::rand(rng);
        let zh = CP::get_zh(vp_setup, vp_circuit_size);

        Ok(Self {
            vp_desc,
            blinding,
            zh,
        })
    }
}
