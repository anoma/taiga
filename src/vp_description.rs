use crate::circuit::circuit_parameters::CircuitParameters;
use crate::circuit::validity_predicate::ValidityPredicate;
use crate::constant::BLIND_ELEMENTS_NUM;
use crate::poseidon::WIDTH_9;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use plonk_core::{prelude::Error, proof_system::VerifierKey};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, Poseidon},
};
use rand::RngCore;

// TODO: add vp_param in future.
#[derive(Debug, Clone)]
pub enum ValidityPredicateDescription<CP: CircuitParameters> {
    // Pack vk into CurveBaseField array.
    Packed(Vec<CP::CurveBaseField>),
    // Compress(Com_q) vk into one CurveBaseField element.
    Compressed(CP::CurveBaseField),
}

impl<CP: CircuitParameters> ValidityPredicateDescription<CP> {
    pub fn from_vp<VP>(
        vp: &mut VP,
        vp_setup: &<CP::CurvePC as PolynomialCommitment<
            CP::CurveScalarField,
            DensePolynomial<CP::CurveScalarField>,
        >>::UniversalParams,
    ) -> Result<Self, Error>
    where
        VP: ValidityPredicate<CP>,
    {
        let vk = vp.get_desc_vp(vp_setup)?;
        Ok(Self::from_vk(&vk))
    }

    pub fn from_vk(vk: &VerifierKey<CP::CurveScalarField, CP::CurvePC>) -> Self {
        let vp_desc = CP::pack_vk(vk);
        Self::Packed(vp_desc)
    }

    pub fn get_pack(&self) -> Option<Vec<CP::CurveBaseField>> {
        match self {
            ValidityPredicateDescription::Packed(v) => Some(v.clone()),
            ValidityPredicateDescription::Compressed(_) => None,
        }
    }

    pub fn get_compress(&self) -> CP::CurveBaseField {
        match self {
            ValidityPredicateDescription::Packed(v) => {
                assert_eq!(v.len(), BLIND_ELEMENTS_NUM * 2);
                let poseidon_param: PoseidonConstants<CP::CurveBaseField> =
                    PoseidonConstants::generate::<WIDTH_9>();
                let mut poseidon =
                    Poseidon::<(), NativeSpec<CP::CurveBaseField, WIDTH_9>, WIDTH_9>::new(
                        &mut (),
                        &poseidon_param,
                    );
                // Compress all elements in vp
                // let hash_vec = v
                //     .chunks_exact(8)
                //     .map(|chunk| {
                //         poseidon.reset(&mut ());
                //         for x in chunk.iter() {
                //             poseidon.input(*x).unwrap();
                //         }
                //         poseidon.output_hash(&mut ())
                //     })
                //     .collect::<Vec<CP::CurveBaseField>>();

                // poseidon.reset(&mut ());
                // for x in hash_vec.iter() {
                //     poseidon.input(*x).unwrap();
                // }

                // Compress x-coordinate blinded elements in vp
                v.iter().step_by(2).for_each(|e| {
                    poseidon.input(*e).unwrap();
                });
                poseidon.output_hash(&mut ())
            }
            ValidityPredicateDescription::Compressed(v) => *v,
        }
    }

    pub fn dummy(rng: &mut impl RngCore) -> Self {
        Self::Compressed(CP::CurveBaseField::rand(rng))
    }

    pub fn to_bits(&self) -> Vec<bool> {
        self.get_compress().into_repr().to_bits_le()
    }
}
