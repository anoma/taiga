// The interfaces may not be perfectly defined, the caller can refine them if needed.

use crate::circuit::{circuit_parameters::CircuitParameters, gadgets::hash::FieldHasherGadget};
// use crate::error::TaigaError;
use crate::note::Note;
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
    // convert the vp variables inside, move out if needed.
    send_vp_bytes: &[bool],
    recv_vp_bytes: &[bool],
) -> Result<(Variable, Vec<Variable>), Error> {
    // Init poseidon hash gadget.
    let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_5>();

    // convert send_vp bits to two variable
    let (mut send_com_fields, send_vp_bits) = bits_to_variables::<CP>(composer, send_vp_bytes);

    // send_com = Com_r(send_vp_hash || nk)
    send_com_fields.push(*nk);
    let address_send = poseidon_param.circuit_hash(composer, &send_com_fields)?;

    // convert recv_vp bits to two variable
    let (recv_vp, _recv_vp_bits) = bits_to_variables::<CP>(composer, recv_vp_bytes);

    // generate address variable
    let mut address_vars = vec![address_send];
    address_vars.extend(recv_vp);
    let address = poseidon_param.circuit_hash(composer, &address_vars)?;
    Ok((address, send_vp_bits))
}

pub fn output_user_address_integrity_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    address_send: &Variable,
    // convert the vp variables inside, move out if needed.
    recv_vp_bytes: &[bool],
) -> Result<(Variable, Vec<Variable>), Error> {
    // Init poseidon hash gadget.
    let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_5>();

    // convert recv_vp bits to two variable
    let (recv_vp, recv_vp_bits) = bits_to_variables::<CP>(composer, recv_vp_bytes);

    // generate address variable
    let mut address_vars = vec![*address_send];
    address_vars.extend(recv_vp);
    let address = poseidon_param.circuit_hash(composer, &address_vars)?;
    Ok((address, recv_vp_bits))
}

pub fn app_integrity_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    // convert the vp variables inside, move out if needed.
    app_vp_bytes: &[bool],
) -> Result<(Variable, Vec<Variable>), Error> {
    // Init poseidon hash gadget.
    let poseidon_param: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_3>();

    // convert app_vp bits to two variable
    let (app_vp_vars, app_bits_var) = bits_to_variables::<CP>(composer, app_vp_bytes);

    // generate address variable
    let app_address =
        poseidon_param.circuit_hash_two(composer, &app_vp_vars[0], &app_vp_vars[1])?;

    Ok((app_address, app_bits_var))
}

pub fn note_commitment_circuit<CP: CircuitParameters>(
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
    address: &Variable,
    app: &Variable,
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

    // cm = crh(address, value, data, rho, psi, rcm, app)
    let poseidon_param_9: PoseidonConstants<CP::CurveScalarField> =
        PoseidonConstants::generate::<WIDTH_9>();
    let mut poseidon_circuit =
        Poseidon::<_, PlonkSpec<WIDTH_9>, WIDTH_9>::new(composer, &poseidon_param_9);
    // Default padding zero
    poseidon_circuit.input(*address).unwrap();
    poseidon_circuit.input(*app).unwrap();
    poseidon_circuit.input(*value).unwrap();
    poseidon_circuit.input(*data).unwrap();
    poseidon_circuit.input(*rho).unwrap();
    poseidon_circuit.input(psi).unwrap();
    poseidon_circuit.input(*rcm).unwrap();
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
) -> (Vec<Variable>, Vec<Variable>) {
    let bit_variables: Vec<Variable> = bits
        .iter()
        .map(|bit| composer.add_input(CP::CurveScalarField::from(*bit as u64)))
        .collect();

    let scalar_variables = bit_variables
        .chunks(CP::CurveScalarField::size_in_bits() - 1)
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

    (scalar_variables, bit_variables)
}

// FIXME: It includes all the variables in input note, maybe it's not necessary.
pub struct ValidityPredicateInputNoteVariables {
    pub sender_addr: Variable,
    pub nk: Variable,
    // send_vp_bits will be used in vp commitment in future.
    pub send_vp_bits: Vec<Variable>,
    pub app_addr: Variable,
    // app_bits will be used in vp commitment in future.
    pub app_bits: Vec<Variable>,
    pub value: Variable,
    pub data: Variable,
    pub nf: Variable,
    pub cm: Variable,
}

// FIXME: It includes all the variables in output note, maybe it's not necessary.
pub struct ValidityPredicateOutputNoteVariables {
    pub recipient_addr: Variable,
    pub recv_vp_bits: Vec<Variable>,
    pub app_addr: Variable,
    pub app_bits: Vec<Variable>,
    pub value: Variable,
    pub data: Variable,
}

pub fn input_note_constraint<CP>(
    note: &Note<CP>,
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
) -> Result<ValidityPredicateInputNoteVariables, Error>
where
    CP: CircuitParameters,
{
    // check user address
    let nk = note.user.send_com.get_nk().unwrap();
    let nk_var = composer.add_input(nk.inner());
    let send_vp = note.user.send_com.get_send_vp().unwrap();
    let (sender_addr, send_vp_bits) = spent_user_address_integrity_circuit::<CP>(
        composer,
        &nk_var,
        &send_vp.to_bits(),
        &note.user.recv_vp.to_bits(),
    )?;

    // check app address
    let (app_addr, app_bits) = app_integrity_circuit::<CP>(composer, &note.app.app_vp.to_bits())?;

    // check note commitment
    let value_var = composer.add_input(CP::CurveScalarField::from(note.value));
    let data_var = composer.add_input(note.data);
    let rho_var = composer.add_input(note.rho.inner());
    let note_rcm_var = composer.add_input(note.rcm);
    let (cm_var, psi_var) = note_commitment_circuit::<CP>(
        composer,
        &sender_addr,
        &app_addr,
        &value_var,
        &data_var,
        &rho_var,
        &note_rcm_var,
    )?;

    let nf = nullifier_circuit::<CP>(composer, &nk_var, &rho_var, &psi_var, &cm_var)?;

    Ok(ValidityPredicateInputNoteVariables {
        sender_addr,
        nk: nk_var,
        send_vp_bits,
        app_addr,
        app_bits,
        value: value_var,
        data: data_var,
        nf,
        cm: cm_var,
    })
}

pub fn output_note_constraint<CP>(
    note: &Note<CP>,
    nf: &Variable,
    composer: &mut StandardComposer<CP::CurveScalarField, CP::InnerCurve>,
) -> Result<ValidityPredicateOutputNoteVariables, Error>
where
    CP: CircuitParameters,
{
    // check user address
    let addr_send = note.user.send_com.get_closed().unwrap();
    let addr_send_var = composer.add_input(addr_send);
    let (recipient_addr, recv_vp_bits) = output_user_address_integrity_circuit::<CP>(
        composer,
        &addr_send_var,
        &note.user.recv_vp.to_bits(),
    )?;

    // check app address
    let (app_addr, app_bits) = app_integrity_circuit::<CP>(composer, &note.app.app_vp.to_bits())?;

    // check and publish note commitment
    let value_var = composer.add_input(CP::CurveScalarField::from(note.value));
    let data_var = composer.add_input(note.data);
    let note_rcm_var = composer.add_input(note.rcm);
    let (cm_var, _psi_var) = note_commitment_circuit::<CP>(
        composer,
        &recipient_addr,
        &app_addr,
        &value_var,
        &data_var,
        nf,
        &note_rcm_var,
    )?;

    composer.public_inputize(&cm_var);

    Ok(ValidityPredicateOutputNoteVariables {
        recipient_addr,
        recv_vp_bits,
        app_addr,
        app_bits,
        value: value_var,
        data: data_var,
    })
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
        let (target_var, _) =
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
        use crate::app::App;
        use crate::circuit::integrity::app_integrity_circuit;
        use crate::circuit::integrity::note_commitment_circuit;
        use crate::circuit::integrity::nullifier_circuit;
        use crate::circuit::integrity::spent_user_address_integrity_circuit;
        use crate::note::Note;
        use crate::nullifier::Nullifier;
        use crate::user::User;
        use ark_std::{test_rng, UniformRand};
        use plonk_core::constraint_system::StandardComposer;
        use rand::Rng;

        let mut rng = test_rng();
        let mut composer = StandardComposer::<Fr, P>::new();

        // Test user address integrity
        // Create a user
        let user = User::<PairingCircuitParameters>::dummy(&mut rng);

        let nk = user.send_com.get_nk().unwrap();
        let nk_var = composer.add_input(nk.inner());
        let send_vp = user.send_com.get_send_vp().unwrap();
        let (address_var, _) = spent_user_address_integrity_circuit::<PairingCircuitParameters>(
            &mut composer,
            &nk_var,
            &send_vp.to_bits(),
            &user.recv_vp.to_bits(),
        )
        .unwrap();
        let expect_address_opaque = user.address().unwrap();
        let expected_address_var = composer.add_input(expect_address_opaque);
        composer.assert_equal(expected_address_var, address_var);
        composer.check_circuit_satisfied();

        // Test app integrity
        // Create a app
        let app = App::<PairingCircuitParameters>::dummy(&mut rng);

        let (app_var, _) =
            app_integrity_circuit::<PairingCircuitParameters>(&mut composer, &app.app_vp.to_bits())
                .unwrap();
        let expected_app_addr = app.address().unwrap();
        let app_expected_var = composer.add_input(expected_app_addr);
        composer.assert_equal(app_expected_var, app_var);
        composer.check_circuit_satisfied();

        // Test note commitment
        // Create a note
        let rho = Nullifier::new(Fr::rand(&mut rng));
        let value: u64 = rng.gen();
        let data = Fr::rand(&mut rng);
        let rcm = Fr::rand(&mut rng);
        let note = Note::new(user, app, value, rho, data, rcm);

        let value_var = composer.add_input(Fr::from(value));
        let data_var = composer.add_input(note.data);
        let rho_var = composer.add_input(note.rho.inner());
        let note_rcm_var = composer.add_input(note.rcm);

        let (cm_var, psi_var) = note_commitment_circuit::<PairingCircuitParameters>(
            &mut composer,
            &address_var,
            &app_var,
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
