use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
use plonk_core::constraint_system::Variable;
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
    use crate::circuit::circuit_parameters::CircuitParameters;
    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::gadgets::field_addition::field_addition_gadget;
    use ark_poly_commit::PolynomialCommitment;
    use merlin::Transcript;
    use plonk_core::proof_system::{Prover, Verifier};
    use std::marker::PhantomData;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type InnerC = <CP as CircuitParameters>::InnerCurve;
    type PC = <CP as CircuitParameters>::CurvePC;

    let rng = &mut ark_std::test_rng();
    let pp = PC::setup(1 << 4, None, rng).unwrap();

    // simple circuit for a test
    let a = F::from(2u64);
    let b = F::from(1u64);
    let c = F::from(3u64);

    let mut prover = Prover::<F, InnerC, PC>::new(b"demo");
    prover.key_transcript(b"key", b"additional seed information");

    field_addition_gadget::<CP>(&mut prover.mut_cs(), &[a, b], &[c]);

    // prover precomputation
    let circuit_size = prover.circuit_bound().next_power_of_two();
    let (ck, vk) = PC::trim(&pp, circuit_size, 0, None).unwrap();
    let desc_vp = prover
        .mut_cs()
        .preprocess_verifier(&ck, &mut Transcript::new(b""), PhantomData::<PC>)
        .unwrap();
    prover.cs.public_inputs.update_size(circuit_size);
    let pub_inp = prover.mut_cs().get_pi().clone();

    // verifier precomputation
    let mut verifier: Verifier<F, InnerC, PC> = Verifier::new(b"demo");
    verifier.key_transcript(b"key", b"additional seed information");
    field_addition_gadget::<CP>(&mut verifier.mut_cs(), &[a, b], &[c]);

    // proof
    let proof = prover.prove(&ck).unwrap();
    // verification
    verifier.verify(&proof, &vk, &pub_inp).unwrap();

    // let blinding_scalar = <PairingCircuitParameters as CircuitParameters>::CurveScalarField::from(1u64);
    // let mut composer = StandardComposer::<
    //     <PairingCircuitParameters as CircuitParameters> ::CurveScalarField,
    //     <PairingCircuitParameters as CircuitParameters>::InnerCurve,
    // >::new();

    // let (ck, vk) = <PC as PolynomialCommitment<F, P>>::trim(&pp, 1<<4, 0, None).unwrap();
    // let mut verifier = plonk_core::proof_system::Verifier::new(b"demo");

    // verifier.preprocess(&ck);

    // let unblinded_vk = verifier.verifier_key.unwrap();
    // let unblinded_q_m = unblinded_vk.arithmetic.q_m.0;

    // let blinding = Blinding::<F>::default();
    // verifier.preprocess_with_blinding(&ck, &blinding);
    // let blinded_vk = verifier.verifier_key.unwrap();
    // let blinded_q_m = blinded_vk.arithmetic.q_m.0;

    //TODO
    //check that blinded_q_m = [blinding.q_m] X + unblinded_q_m
    //blinding_gadget(&mut composer, &[a, b], &[c]);
    // composer.check_circuit_satisfied();
}
