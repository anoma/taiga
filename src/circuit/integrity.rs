use crate::circuit::{circuit_parameters::CircuitParameters, gadgets::hash::FieldHasherGadget};
use crate::error::TaigaError;
use crate::poseidon::WIDTH_5;
use ark_ff::{Field, One, PrimeField};
use plonk_core::{constraint_system::StandardComposer, prelude::Variable};
use plonk_hashing::poseidon::constants::PoseidonConstants;

pub fn address_integrity_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    nk: &Variable,
    rcm: &Variable,
    // convert the vp variables inside, move out if needed.
    send_vp_bytes: &[bool],
    recv_vp_bytes: &[bool],
) -> Result<Variable, TaigaError> {
    // Init poseidon hash gadget.
    let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_5>();

    // convert send_vp bits to two variable
    let mut address_send_fields = bits_to_variables::<CP>(composer, send_vp_bytes);

    // address_send = Com_r( Com_q(send_vp) || nk )
    address_send_fields.push(*nk);
    let address_send = poseidon_param.circuit_hash(composer, &address_send_fields)?;

    // convert recv_vp bits to two variable
    let address_recv = bits_to_variables::<CP>(composer, recv_vp_bytes);

    // generate address variable
    let mut address_vars = vec![address_send];
    address_vars.extend(address_recv);
    address_vars.push(*rcm);
    poseidon_param.circuit_hash(composer, &address_vars)
}

// To keep consistent with crate::utils::bytes_to_fields
// The bits are from unformatted bytes or non-CP::CurveScalarField type.
// The bits can not be from CP::CurveScalarField, it will have one bit loss.
pub fn bits_to_variables<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    bits: &[bool],
) -> Vec<Variable> {
    let bit_variables: Vec<Variable> = bits
        .iter()
        .map(|bit| composer.add_input(CP::CurveScalarField::from(*bit as u64)))
        .collect();

    let ret = bit_variables
        .chunks((CP::CurveScalarField::size_in_bits() - 1) as usize)
        .map(|elt| {
            let mut accumulator_var = composer.zero_var();
            for (power, bit) in elt.iter().enumerate() {
                composer.boolean_gate(*bit);

                let two_pow = CP::CurveScalarField::from(2u64).pow([power as u64, 0, 0, 0]);

                accumulator_var = composer.arithmetic_gate(|gate| {
                    gate.witness(*bit, accumulator_var, None)
                        .add(two_pow, CP::CurveScalarField::one())
                });
            }
            accumulator_var
        })
        .collect();

    ret
}

#[test]
fn test_bits_to_variables() {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
    type Fr = <PairingCircuitParameters as CircuitParameters>::CurveScalarField;
    type Curv = <PairingCircuitParameters as CircuitParameters>::InnerCurve;
    type Fq = <PairingCircuitParameters as CircuitParameters>::CurveBaseField;
    use crate::utils::bits_to_fields;
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::{test_rng, UniformRand};
    use plonk_core::constraint_system::StandardComposer;

    let mut rng = test_rng();
    let src_scalar = Fq::rand(&mut rng);
    let src_scalar_bits = src_scalar.into_repr().to_bits_le();

    // inside-circuit convert
    let mut composer = StandardComposer::<Fr, Curv>::new();
    let target_var = bits_to_variables::<PairingCircuitParameters>(&mut composer, &src_scalar_bits);
    composer.check_circuit_satisfied();

    println!(
        "circuit size of bits_to_variables: {}",
        composer.circuit_bound()
    );

    // out-of-circuit convert, expect result
    let target_expect = bits_to_fields::<Fr>(&src_scalar_bits);

    assert_eq!(target_var.len(), target_expect.len());
    for i in 0..target_var.len() {
        let expected_var = composer.add_input(target_expect[i]);
        composer.assert_equal(expected_var, target_var[i]);
    }
    composer.check_circuit_satisfied();
}

#[test]
fn test_address_integrity_circuit() {
    use crate::address::Address;
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
    use ark_std::test_rng;
    type Fr = <PairingCircuitParameters as CircuitParameters>::CurveScalarField;
    type Curv = <PairingCircuitParameters as CircuitParameters>::InnerCurve;
    type Fq = <PairingCircuitParameters as CircuitParameters>::CurveBaseField;

    let mut rng = test_rng();
    let address = Address::<PairingCircuitParameters>::new(&mut rng);

    // address integrity circuit
    let mut composer = StandardComposer::<Fr, Curv>::new();
    let nk_var = composer.add_input(address.nk.inner());
    let rcm_var = composer.add_input(address.rcm);
    let address_var = address_integrity_circuit::<PairingCircuitParameters>(
        &mut composer,
        &nk_var,
        &rcm_var,
        &address.send_vp.to_bits(),
        &address.recv_vp.to_bits(),
    )
    .unwrap();

    composer.check_circuit_satisfied();

    println!(
        "circuit size of address_integrity_circuit: {}",
        composer.circuit_bound()
    );

    // check expect address
    let expect_address_opaque = address.opaque_native().unwrap();
    let expected_var = composer.add_input(expect_address_opaque);
    composer.assert_equal(expected_var, address_var);
    composer.check_circuit_satisfied();
}
