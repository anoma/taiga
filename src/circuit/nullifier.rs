use crate::circuit::{circuit_parameters::CircuitParameters, hash_gadget::BinaryHasherGadget};
use crate::error::TaigaError;
use crate::nullifier_key::NullifierDerivingKey;
use crate::poseidon::{BinaryHasher, WIDTH_3};
use ark_ec::{
    twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve, ProjectiveCurve,
};
use ark_ff::{BigInteger, One, PrimeField};
use plonk_core::{
    constraint_system::{ecc::Point, StandardComposer},
    prelude::Variable,
};
use plonk_hashing::poseidon::constants::PoseidonConstants;

/// The unique nullifier.
#[derive(Copy, Debug, Clone)]
pub struct Nullifier<CP: CircuitParameters>(CP::CurveScalarField);

impl<CP: CircuitParameters> Nullifier<CP> {
    // $nf =Extract_P([PRF_{nk}(\rho) = \psi \ mod \ q] * K + cm)$
    pub fn derive_native(
        nk: &NullifierDerivingKey<CP::CurveScalarField>,
        rho: &CP::CurveScalarField,
        psi: &CP::CurveScalarField,
        cm: &TEGroupAffine<CP::InnerCurve>,
    ) -> Self {
        // Init poseidon param.
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_3>();
        let prf_nk_rho = poseidon_param.native_hash_two(&nk.inner(), rho).unwrap();
        // This requires CP::CurveScalarField is smaller than CP::InnerCurveScalarField
        let scalar_repr = (prf_nk_rho + psi).into_repr();
        let scalar = CP::InnerCurveScalarField::from_le_bytes_mod_order(&scalar_repr.to_bytes_le());

        let ret = TEGroupAffine::prime_subgroup_generator()
            .mul(scalar)
            .into_affine()
            + cm;

        Nullifier(ret.x)
    }

    // Nullifier derive circuit,
    pub fn derive_circuit(
        composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
        nk: &Variable,
        rho: &Variable,
        psi: &Variable,
        cm: &Point<CP::InnerCurve>,
    ) -> Result<Variable, TaigaError> {
        let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_3>();
        let prf_ret = poseidon_param.circuit_hash_two(composer, nk, rho)?;

        // scalar = prf_nk(rho) + psi
        let scalar = composer.arithmetic_gate(|gate| {
            gate.witness(prf_ret, *psi, None)
                .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
        });

        // point_scalar = scalar * generator
        let point_scalar =
            composer.fixed_base_scalar_mul(scalar, TEGroupAffine::prime_subgroup_generator());

        // nullifier_point = point_scalar + cm
        let nullifier_point = composer.point_addition_gate(point_scalar, *cm);

        // public the nullifier
        let nullifier_variable = nullifier_point.x();
        composer.public_inputize(nullifier_variable);

        // return the nullifier variable.(if we don't need it, pls get rid of it)
        Ok(*nullifier_variable)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(CP::CurveScalarField::from_le_bytes_mod_order(bytes))
    }

    pub fn inner(&self) -> CP::CurveScalarField {
        self.0
    }
}

#[test]
fn nullifier_circuit_test() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
    use ark_bls12_377::Fr;
    use ark_ed_on_bls12_377::EdwardsParameters as Curv;
    use ark_std::{test_rng, UniformRand};
    use plonk_core::constraint_system::{ecc::Point, StandardComposer};

    let mut rng = test_rng();
    let nk = NullifierDerivingKey::<
        <PairingCircuitParameters as CircuitParameters>::CurveScalarField,
    >::rand(&mut rng);
    let rho = <PairingCircuitParameters as CircuitParameters>::CurveScalarField::rand(&mut rng);
    let psi = <PairingCircuitParameters as CircuitParameters>::CurveScalarField::rand(&mut rng);
    let cm = TEGroupAffine::prime_subgroup_generator();
    let expect_nf = Nullifier::<PairingCircuitParameters>::derive_native(&nk, &rho, &psi, &cm);

    // Nullifier derive circuit
    let mut composer = StandardComposer::<Fr, Curv>::new();
    let variable_nk = composer.add_input(nk.inner());
    let variable_rho = composer.add_input(rho);
    let psi_variable = composer.add_input(psi);
    let cm_x = composer.add_input(cm.x);
    let cm_y = composer.add_input(cm.y);
    let cm_variable = Point::<Curv>::new(cm_x, cm_y);

    let nullifier_variable = Nullifier::<PairingCircuitParameters>::derive_circuit(
        &mut composer,
        &variable_nk,
        &variable_rho,
        &psi_variable,
        &cm_variable,
    )
    .unwrap();

    // check nullifier circuit.
    composer.check_circuit_satisfied();

    // check expect_nf
    let expected_var = composer.add_input(expect_nf.inner());
    composer.assert_equal(expected_var, nullifier_variable);
    composer.check_circuit_satisfied();

    println!(
        "circuit size for nf derivation: {}",
        composer.circuit_bound()
    );
}
