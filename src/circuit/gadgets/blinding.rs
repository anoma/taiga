use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
use plonk_core::{circuit::Circuit, prelude::StandardComposer};

type CircuitPoint = plonk_core::constraint_system::ecc::Point<
    <PairingCircuitParameters as CircuitParameters>::InnerCurve,
>;
use ark_poly_commit::sonic_pc::CommitterKey;

type InnerCurve = ark_bls12_377::Bls12_377;

pub fn blinding_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<
        <CP as CircuitParameters>::CurveBaseField,
        <CP as CircuitParameters>::Curve,
    >,
    private_inputs: &[<CP as CircuitParameters>::CurveBaseField],
    public_inputs: &[<CP as CircuitParameters>::CurveBaseField],
    // ) -> CircuitPoint {
) {
    // let generator = TEGroupAffine::<CP::Curve>::prime_subgroup_generator();
    // let p = composer.fixed_base_scalar_mul(blinding_scalar, generator); //todo this is totally false
    // composer.point_addition_gate(p, polynomial) // [blinding_scalar] * ck_1 + polynomial
}

#[test]
fn test_blinding_gadget() {
    use crate::circuit::validity_predicate::ValidityPredicate;
    use ark_poly_commit::PolynomialCommitment;

    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::gadgets::field_addition::field_addition_gadget;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type InnerC = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;
    type OuterPC = <CP as CircuitParameters>::OuterCurvePC;

    // a simple VP
    let rng = &mut rand::thread_rng();
    let setup = PC::setup(1 << 4, None, rng).unwrap();

    let (a, b, c) = (F::from(2u64), F::from(1u64), F::from(3u64));

    let vp = ValidityPredicate::<CP>::new(
        &setup,
        field_addition_gadget::<CP>,
        &[a, b],
        &[c],
        true,
        rng,
    );
    vp.verify();

    // blinding circuit
    // let setup_inner = OuterPC::setup(1 << 4, None, rng).unwrap();

    // let unblinded_vk = vp.vk;
    // let unblinded_q_m = unblinded_vk.arithmetic.q_m.0;

    // let blinding = Blinding::<F>::default();
    // verifier.preprocess_with_blinding(&ck, &blinding);
    // let blinded_vk = verifier.verifier_key.unwrap();
    // let blinded_q_m = blinded_vk.arithmetic.q_m.0;
}
