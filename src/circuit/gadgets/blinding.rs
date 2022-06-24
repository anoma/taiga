use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
use ark_ec::{twisted_edwards_extended::GroupAffine as TEGroupAffine};
use plonk_core::prelude::{StandardComposer, Point};

type CircuitPoint = plonk_core::constraint_system::ecc::Point<
    <PairingCircuitParameters as CircuitParameters>::InnerCurve,
>;

type InnerCurve = ark_bls12_377::Bls12_377;

pub fn blinding_gadget<CP: CircuitParameters>(
    composer: &mut StandardComposer<
        CP::CurveBaseField,
        CP::Curve,
    >,
    private_inputs: &[CP::CurveBaseField],
    public_inputs: &[CP::CurveBaseField],
) -> Point<CP::Curve> {
    // parse the private inputs
    let q_l = composer.add_affine(TEGroupAffine::<CP::Curve>::new(private_inputs[0], private_inputs[1]));
    let b0 = composer.add_input(private_inputs[2]);
    // parse the public inputs (todo is Com(Z_H) a public input?)
    let com_z_h = TEGroupAffine::<CP::Curve>::new(public_inputs[0], public_inputs[1]);
    // constraints
    let b0_zh = composer.fixed_base_scalar_mul(b0, com_z_h);
    composer.point_addition_gate(q_l, b0_zh)
}

#[test]
fn test_blinding_gadget() {
    use crate::circuit::validity_predicate::ValidityPredicate;
    use std::ops::Neg;
    use ark_poly_commit::PolynomialCommitment;
    use ark_ec::{
        AffineCurve,
        ProjectiveCurve,
        twisted_edwards_extended::GroupAffine as TEGroupAffine,
        short_weierstrass_jacobian::GroupAffine as SWGroupAffine,
    };
    use ark_ff::{field_new, PrimeField, One, BigInteger};

    use crate::circuit::circuit_parameters::PairingCircuitParameters as CP;
    use crate::circuit::gadgets::field_addition::field_addition_gadget;
    use crate::circuit::blinding_circuit::BlindingCircuit;

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


    // blinding circuit

    // conversion to TE model
    fn ws_to_te(p: SWGroupAffine<Curve>) -> TEGroupAffine<Curve> {
        // for bls12_377
        // values available in https://github.com/arkworks-rs/curves/blob/master/bls12_377/src/curves/g1.rs
        let x = p.x;
        let y = p.y;
        let alpha = -BaseField::one();
        let s = field_new!(BaseField, "10189023633222963290707194929886294091415157242906428298294512798502806398782149227503530278436336312243746741931");
        let sqrt_te1a = field_new!(BaseField, "23560188534917577818843641916571445935985386319233886518929971599490231428764380923487987729215299304184915158756");
        let x_te = (x-alpha)*sqrt_te1a/y;
        let y_te = (s*(x-alpha)-BaseField::one()) / (s*(x-alpha)+BaseField::one());
        TEGroupAffine::<Curve>::new(x_te, y_te)
    }

    let unblinded_q_l = ws_to_te(vp.desc_vp.arithmetic.q_l.0);
    let blinded_q_l = ws_to_te(vp.verifier.verifier_key.unwrap().arithmetic.q_l.0);

    let blinding_factor = vp.blind_rand;
    let b0 = blinding_factor.q_l;

    // [b0 * Z_H + q_l] ?= b0 *[Z_H] + [q_l]
    let n = vp.ck.powers_of_g.len();
    let com_g_n = vp.ck.powers_of_g[n-1];//
    let com_g_0 = vp.ck.powers_of_g[0];
    let com_z_h = ws_to_te(com_g_n + com_g_0.neg());

    assert_eq!(com_z_h.mul(b0).into_affine() + unblinded_q_l, blinded_q_l);

    // circuit
    let setup_inner = OuterPC::setup(1 << 4, None, rng).unwrap();

    let a = blinding_gadget::<CP>;
    let blinding_vp = BlindingCircuit::<CP>::new(
        &setup_inner,
        blinding_gadget::<CP>,
        &[unblinded_q_l.x, unblinded_q_l.y, BaseField::from_le_bytes_mod_order(&b0.into_repr().to_bytes_le())],
        &[com_z_h.x, com_z_h.y],
    );
    blinding_vp.verify();

}
