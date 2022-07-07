// The interfaces may not perfectly defined, the caller can refine them if needed.

use crate::circuit::{circuit_parameters::CircuitParameters, gadgets::hash::FieldHasherGadget};
// use crate::error::TaigaError;
use crate::poseidon::{WIDTH_3, WIDTH_5, WIDTH_9};
use ark_ff::{Field, One, PrimeField};
use plonk_core::{
    constraint_system::StandardComposer,
    prelude::{Error, Variable},
};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon::{PlonkSpec, Poseidon},
};

pub fn spent_user_address_integrity_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    nk: &Variable,
    rcm: &Variable,
    // convert the vp variables inside, move out if needed.
    send_vp_bytes: &[bool],
    recv_vp_bytes: &[bool],
) -> Result<Variable, Error> {
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

pub fn output_user_address_integrity_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    address_send: &Variable,
    rcm: &Variable,
    // convert the vp variables inside, move out if needed.
    recv_vp_bytes: &[bool],
) -> Result<Variable, Error> {
    // Init poseidon hash gadget.
    let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_5>();

    // convert recv_vp bits to two variable
    let address_recv = bits_to_variables::<CP>(composer, recv_vp_bytes);

    // generate address variable
    let mut address_vars = vec![*address_send];
    address_vars.extend(address_recv);
    address_vars.push(*rcm);
    poseidon_param.circuit_hash(composer, &address_vars)
}

pub fn token_integrity_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    rcm: &Variable,
    // convert the vp variables inside, move out if needed.
    token_vp_bytes: &[bool],
) -> Result<Variable, Error> {
    // Init poseidon hash gadget.
    let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_5>();

    // convert send_vp bits to two variable
    let mut token_fields = bits_to_variables::<CP>(composer, token_vp_bytes);

    // address_send = Com_r( Com_q(send_vp) || nk )
    token_fields.push(*rcm);
    poseidon_param.circuit_hash(composer, &token_fields)
}

pub fn note_commitment_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    address: &Variable,
    token: &Variable,
    value: &Variable, // To be decided where to constrain the range of value, add the range constraints here first.
    data: &Variable,
    rho: &Variable,
    rcm: &Variable,
) -> Result<(Variable, Variable), Error> {
    // constrain the value to be 64 bit
    composer.range_gate(*value, 64);

    // psi = prf(rho, rcm)
    let poseidon_param_3: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_3>();
    let psi = poseidon_param_3.circuit_hash_two(composer, rho, rcm)?;

    // cm = crh(address, token, value, data, rho, psi, rcm)
    let note_variables = vec![*address, *token, *value, *data, *rho, psi, *rcm];
    let poseidon_param_9: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_9>();
    let mut poseidon_circuit =
        Poseidon::<_, PlonkSpec<WIDTH_9>, WIDTH_9>::new(composer, &poseidon_param_9);
    // Default padding zero
    note_variables.into_iter().for_each(|f| {
        poseidon_circuit.input(f).unwrap();
    });
    Ok((poseidon_circuit.output_hash(composer), psi))
}

// cm is a scalar
pub fn nullifier_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    nk: &Variable,
    rho: &Variable,
    psi: &Variable,
    cm: &Variable,
) -> Result<Variable, Error> {
    let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_5>();
    let variavle_vec = vec![*nk, *rho, *psi, *cm];
    let nullifier_variable = poseidon_param.circuit_hash(composer, &variavle_vec)?;

    // public the nullifier
    composer.public_inputize(&nullifier_variable);

    // return the nullifier variable.(if we don't need it, pls get rid of it)
    Ok(nullifier_variable)
}

// cm is a point
// pub fn nullifier_circuit<CP: CircuitParameters>(
//     composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
//     nk: &Variable,
//     rho: &Variable,
//     psi: &Variable,
//     cm: &Point<CP::InnerCurve>,
// ) -> Result<Variable, Error> {
//     let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
//         PoseidonConstants::generate::<WIDTH_3>();
//     let prf_ret = poseidon_param.circuit_hash_two(composer, nk, rho)?;

//     // scalar = prf_nk(rho) + psi
//     let scalar = composer.arithmetic_gate(|gate| {
//         gate.witness(prf_ret, *psi, None)
//             .add(CP::CurveScalarField::one(), CP::CurveScalarField::one())
//     });

//     // point_scalar = scalar * generator
//     let point_scalar =
//         composer.fixed_base_scalar_mul(scalar, TEGroupAffine::prime_subgroup_generator());

//     // nullifier_point = point_scalar + cm
//     let nullifier_point = composer.point_addition_gate(point_scalar, *cm);

//     // public the nullifier
//     let nullifier_variable = nullifier_point.x();
//     composer.public_inputize(nullifier_variable);

//     // return the nullifier variable.(if we don't need it, pls get rid of it)
//     Ok(*nullifier_variable)
// }

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

mod test {
    use crate::circuit::circuit_parameters::{CircuitParameters, PairingCircuitParameters};
    type Fr = <PairingCircuitParameters as CircuitParameters>::CurveScalarField;
    type P = <PairingCircuitParameters as CircuitParameters>::InnerCurve;
    type Fq = <PairingCircuitParameters as CircuitParameters>::CurveBaseField;

    #[test]
    fn test_bits_to_variables() {
        use crate::circuit::integrity::bits_to_variables;
        use crate::utils::bits_to_fields;
        use ark_ff::{BigInteger, PrimeField};
        use ark_std::{test_rng, UniformRand};
        use plonk_core::constraint_system::StandardComposer;

        let mut rng = test_rng();
        let src_scalar = Fq::rand(&mut rng);
        let src_scalar_bits = src_scalar.into_repr().to_bits_le();

        // inside-circuit convert
        let mut composer = StandardComposer::<Fr, P>::new();
        let target_var =
            bits_to_variables::<PairingCircuitParameters>(&mut composer, &src_scalar_bits);
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
    fn test_integrity_circuit() {
        use crate::circuit::integrity::note_commitment_circuit;
        use crate::circuit::integrity::nullifier_circuit;
        use crate::circuit::integrity::spent_user_address_integrity_circuit;
        use crate::circuit::integrity::token_integrity_circuit;
        use crate::note::Note;
        use crate::nullifier::Nullifier;
        use crate::token::TokenAddress;
        use crate::user_address::UserAddress;
        use ark_std::{test_rng, UniformRand};
        use plonk_core::constraint_system::StandardComposer;
        use rand::Rng;

        let mut rng = test_rng();
        let mut composer = StandardComposer::<Fr, P>::new();

        // Test user address integrity
        // Create a user address
        let address = UserAddress::<PairingCircuitParameters>::new(&mut rng);

        let nk = address.send_addr.get_nk().unwrap();
        let nk_var = composer.add_input(nk.inner());
        let address_rcm_var = composer.add_input(address.rcm);
        let send_vp = address.send_addr.get_send_vp().unwrap();
        let address_var = spent_user_address_integrity_circuit::<PairingCircuitParameters>(
            &mut composer,
            &nk_var,
            &address_rcm_var,
            &send_vp.to_bits(),
            &address.recv_vp.to_bits(),
        )
        .unwrap();
        let expect_address_opaque = address.opaque_native().unwrap();
        let expected_address_var = composer.add_input(expect_address_opaque);
        composer.assert_equal(expected_address_var, address_var);
        composer.check_circuit_satisfied();

        // Test token integrity
        // Create a token
        let token = TokenAddress::<PairingCircuitParameters>::new(&mut rng);

        let token_rcm_var = composer.add_input(token.rcm);
        let token_var = token_integrity_circuit::<PairingCircuitParameters>(
            &mut composer,
            &token_rcm_var,
            &token.token_vp.to_bits(),
        )
        .unwrap();
        let expect_token_opaque = token.opaque_native().unwrap();
        let token_expected_var = composer.add_input(expect_token_opaque);
        composer.assert_equal(token_expected_var, token_var);
        composer.check_circuit_satisfied();

        // Test note commitment
        // Create a note
        let rho = Nullifier::new(Fr::rand(&mut rng));
        let value: u64 = rng.gen();
        let data = Fr::rand(&mut rng);
        let rcm = Fr::rand(&mut rng);
        let note = Note::new(address, token, value, rho, data, rcm);

        let value_var = composer.add_input(Fr::from(value));
        let data_var = composer.add_input(note.data);
        let rho_var = composer.add_input(note.rho.inner());
        let note_rcm_var = composer.add_input(note.rcm);

        let (cm_var, psi_var) = note_commitment_circuit::<PairingCircuitParameters>(
            &mut composer,
            &address_var,
            &token_var,
            &value_var,
            &data_var,
            &rho_var,
            &note_rcm_var,
        )
        .unwrap();

        let expect_cm = note.commitment().unwrap();
        let cm_expected_var = composer.add_input(expect_cm.inner());
        composer.assert_equal(cm_expected_var, cm_var);
        composer.check_circuit_satisfied();

        // Test nullifier
        let expect_nf = Nullifier::<PairingCircuitParameters>::derive_native(
            &nk, &note.rho, &note.psi, &expect_cm,
        );
        let nullifier_variable = nullifier_circuit::<PairingCircuitParameters>(
            &mut composer,
            &nk_var,
            &rho_var,
            &psi_var,
            &cm_var,
        )
        .unwrap();
        let nf_expected_var = composer.add_input(expect_nf.inner());
        composer.assert_equal(nf_expected_var, nullifier_variable);
        composer.check_circuit_satisfied();

        println!(
            "circuit size of test_integrity_circuit: {}",
            composer.circuit_bound()
        );
    }
}
