use crate::circuit::circuit_parameters::CircuitParameters;
use crate::poseidon::WIDTH_3;
use ark_ec::{
    twisted_edwards_extended::GroupAffine as TEGroupAffine, AffineCurve, ProjectiveCurve,
};
use ark_ff::{BigInteger, PrimeField};
use blake2b_simd::Params;
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{NativeSpec, Poseidon},
};
use rand::RngCore;

const PRF_NK_PERSONALIZATION: &[u8; 12] = b"Taiga_PRF_NK";

/// The nullifier key for note spending.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NullifierDerivingKey<F: PrimeField>(F);

/// The unique nullifier.
pub struct Nullifier<CP: CircuitParameters>(CP::CurveScalarField);

impl<F: PrimeField> NullifierDerivingKey<F> {
    pub fn rand(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self::prf_nk(&bytes)
    }

    pub fn new_from(rng_bytes: &[u8; 32]) -> Self {
        Self::prf_nk(rng_bytes)
    }

    fn prf_nk(r: &[u8]) -> Self {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PRF_NK_PERSONALIZATION)
            .to_state();
        h.update(r);
        Self::from_bytes(h.finalize().as_bytes())
    }

    pub fn inner(&self) -> F {
        self.0
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(F::from_le_bytes_mod_order(bytes))
    }
}

impl<CP: CircuitParameters> Nullifier<CP> {
    // $nf =Extract_P([PRF_{nk}(\rho) = \psi \ mod \ q] * K + cm)$
    pub fn derive(
        nk: &NullifierDerivingKey<CP::CurveScalarField>,
        rho: &CP::CurveScalarField,
        psi: &CP::CurveScalarField,
        cm: &TEGroupAffine<CP::InnerCurve>,
    ) -> Self {
        // This requires CP::CurveScalarField is smaller than CP::InnerCurveScalarField
        let scalar_repr = (Self::prf_nf(nk, rho) + psi).into_repr();
        let scalar = CP::InnerCurveScalarField::from_le_bytes_mod_order(&scalar_repr.to_bytes_le());

        let ret = TEGroupAffine::prime_subgroup_generator()
            .mul(scalar)
            .into_affine()
            + cm;

        Nullifier(ret.x)
    }

    // Uses poseidon hash with 2 inputs as prf_nf.
    fn prf_nf(
        nk: &NullifierDerivingKey<CP::CurveScalarField>,
        rho: &CP::CurveScalarField,
    ) -> CP::CurveScalarField {
        let param: PoseidonConstants<CP::CurveScalarField> =
            PoseidonConstants::generate::<WIDTH_3>();
        let mut poseidon = Poseidon::<(), NativeSpec<CP::CurveScalarField, WIDTH_3>, WIDTH_3>::new(
            &mut (),
            &param,
        );
        poseidon.input(nk.inner()).unwrap();
        poseidon.input(*rho).unwrap();
        poseidon.output_hash(&mut ())
    }

    pub fn to_bytes(self) -> Vec<u8> {
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
    use crate::circuit::hash_gadget::BinaryHasherGadget;
    use crate::poseidon::POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2;
    use ark_bls12_377::Fr;
    use ark_ed_on_bls12_377::EdwardsParameters as Curv;
    use ark_std::{test_rng, One, UniformRand};
    use plonk_core::constraint_system::{ecc::Point, StandardComposer};

    let mut rng = test_rng();
    let nk = NullifierDerivingKey::<
        <PairingCircuitParameters as CircuitParameters>::CurveScalarField,
    >::rand(&mut rng);
    let rho = <PairingCircuitParameters as CircuitParameters>::CurveScalarField::rand(&mut rng);
    let psi = <PairingCircuitParameters as CircuitParameters>::CurveScalarField::rand(&mut rng);
    let cm = TEGroupAffine::prime_subgroup_generator();
    let expect_nf = Nullifier::<PairingCircuitParameters>::derive(&nk, &rho, &psi, &cm);

    // Nullifier derive circuit
    // TODO: we need add the nullifier derive circuit to spend circuit.
    let mut composer = StandardComposer::<Fr, Curv>::new();

    // prf_ret = prf_nk(rho)
    let variable_nk = composer.add_input(nk.inner());
    let variable_rho = composer.add_input(rho);
    let hash_gadget: PoseidonConstants<Fr> = POSEIDON_HASH_PARAM_BLS12_377_SCALAR_ARITY2.clone();
    let prf_ret = hash_gadget
        .hash_two(&mut composer, &variable_nk, &variable_rho)
        .unwrap();

    // scalar = prf_nk(rho) + psi
    let psi_variable = composer.add_input(psi);
    let scalar = composer.arithmetic_gate(|gate| {
        gate.witness(prf_ret, psi_variable, None)
            .add(Fr::one(), Fr::one())
    });

    // point_scalar = scalar * generator
    let point_scalar =
        composer.fixed_base_scalar_mul(scalar, TEGroupAffine::prime_subgroup_generator());

    // ret = point_scalar + cm
    let cm_x = composer.add_input(cm.x);
    let cm_y = composer.add_input(cm.y);
    let cm_point = Point::new(cm_x, cm_y);
    let ret = composer.point_addition_gate(point_scalar, cm_point);
    composer.check_circuit_satisfied();

    // check expect_nf
    let expected_var = composer.add_input(expect_nf.inner());
    composer.assert_equal(expected_var, ret.x().clone());
    composer.check_circuit_satisfied();

    println!(
        "circuit size for nf derivation: {}",
        composer.circuit_bound()
    );
}
