use crate::circuit::circuit_parameters::{PairingCircuitParameters, CircuitParameters};
use ark_ec::bls12::Bls12;
use plonk_core::prelude::StandardComposer;
use plonk_core::constraint_system::Variable;
type CircuitPoint = plonk_core::constraint_system::ecc::Point<<PairingCircuitParameters as CircuitParameters>::InnerCurve>;
use ark_poly_commit::sonic_pc::CommitterKey;

type InnerCurve = ark_bls12_377::Bls12_377;

pub fn blinding_gadget(
    composer: &mut StandardComposer<<PairingCircuitParameters as CircuitParameters>::CurveScalarField, <PairingCircuitParameters as CircuitParameters>::InnerCurve>,
    blinding_scalar: Variable, 
    polynomial: CircuitPoint,
    ck: &CommitterKey<InnerCurve>,
    
) -> CircuitPoint {

    let p = composer.fixed_base_scalar_mul(blinding_scalar, ck.powers_of_g[1]); //todo: is this the right power?

    composer.point_addition_gate(p, polynomial) // [blinding_scalar] * ck_1 + polynomial
}

use ark_poly_commit::PolynomialCommitment;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;

#[test]
fn test_blinding_gadget() {
    use ark_bls12_377::{G1Affine, Bls12_377};
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
    use plonk_core::constraint_system::StandardComposer;
    use plonk_core::proof_system::Blinding;

    let blinding_scalar = <PairingCircuitParameters as CircuitParameters>::CurveScalarField::from(1u64);
    let mut composer = StandardComposer::<
        <PairingCircuitParameters as CircuitParameters> ::CurveScalarField,
        <PairingCircuitParameters as CircuitParameters>::InnerCurve,
    >::new();

    type F = <PairingCircuitParameters as CircuitParameters> ::CurveScalarField;
    type P = DensePolynomial<F>;
    type PC = plonk_core::commitment::KZG10<Bls12_377>;

    let rng = &mut ark_std::test_rng();
    let pp = PC::setup(1 << 4, None, rng).unwrap();
    
    let (ck, vk) = <PC as PolynomialCommitment<F, P>>::trim(&pp, circuit.circuit_bound(), 0, None).unwrap();
    let mut verifier = plonk_core::proof_system::Verifier::new(b"demo");

    verifier.preprocess(&ck);

    let unblinded_vk = verifier.verifier_key.unwrap();
    let unblinded_q_m = unblinded_vk.arithmetic.q_m.0;

    let blinding = Blinding::<F>::default();
    verifier.preprocess_with_blinding(&ck, &blinding);
    let blinded_vk = verifier.verifier_key.unwrap();
    let blinded_q_m = blinded_vk.arithmetic.q_m.0;

    //TODO 
    //check that blinded_q_m = [blinding.q_m] X + unblinded_q_m
    //blinding_gadget(&mut composer, &[a, b], &[c]); 
    composer.check_circuit_satisfied();
}
