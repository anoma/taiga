use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
use ark_ec::twisted_edwards_extended::GroupAffine as TEGroupAffine;
use plonk_core::prelude::{Point, StandardComposer};

type CircuitPoint = plonk_core::constraint_system::ecc::Point<
    <PairingCircuitParameters as CircuitParameters>::InnerCurve,
>;

type InnerCurve = ark_bls12_377::Bls12_377;

pub fn blinding_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveBaseField, CP::Curve>,
    private_inputs: &[CP::CurveBaseField],
    public_inputs: &[CP::CurveBaseField],
) -> Vec<Point<CP::Curve>> {
    // parse the public inputs (todo is Com(Z_H) a public input?)
    let com_z_h = TEGroupAffine::<CP::Curve>::new(public_inputs[0], public_inputs[1]);

    assert_eq!(private_inputs.len() % 3, 0);
    let mut i = 0;
    let mut q: Point<CP::Curve>;
    let mut res: Vec<Point<CP::Curve>> = vec![];
    while i < private_inputs.len() {
        // parse the private inputs
        q = composer.add_affine(TEGroupAffine::<CP::Curve>::new(
            private_inputs[i],
            private_inputs[i + 1],
        ));
        let b = composer.add_input(private_inputs[i + 2]);
        // constraints
        let b0_zh = composer.fixed_base_scalar_mul(b, com_z_h);
        res.push(composer.point_addition_gate(q, b0_zh));

        i += 3;
    }
    res
}

#[test]
fn test_blinding_gadget() {
    use crate::circuit::validity_predicate::ValidityPredicate;
    use ark_poly_commit::PolynomialCommitment;

    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::gadgets::field_addition::field_addition_gadget;

    type F = <CP as CircuitParameters>::CurveScalarField;
    type BaseField = <CP as CircuitParameters>::CurveBaseField;
    type InnerC = <CP as CircuitParameters>::InnerCurve;
    type Curve = <CP as CircuitParameters>::Curve;
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

    // blinding circuit inputs
    let (private_inputs, public_inputs) = CP::get_inputs(&vp);
    // let blinded_q_l = ws_to_te(vp.verifier.verifier_key.unwrap().arithmetic.q_l.0);

    let mut blinding_composer = StandardComposer::<
        <CP as CircuitParameters>::CurveBaseField,
        <CP as CircuitParameters>::Curve,
    >::new();
    blinding_gadget::<CP>(&mut blinding_composer, &private_inputs, &public_inputs);
    blinding_composer.check_circuit_satisfied();
    println!("circuit size: {}", blinding_composer.circuit_bound());
}
