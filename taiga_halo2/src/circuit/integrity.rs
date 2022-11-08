use std::ops::Neg;

use crate::circuit::gadgets::{assign_free_advice, AddChip, AddInstructions, MulChip, MulConfig, MulInstructions, AddConfig};
use crate::circuit::note_circuit::{note_commitment_gadget, NoteCommitmentChip};
use crate::constant::{
    NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentFixedBasesFull,
    NoteCommitmentHashDomain, NullifierK,
};
use crate::note::Note;
use ff::{PrimeField, Field};
use group::Curve;
use halo2_gadgets::ecc::EccInstructions;
use halo2_gadgets::utilities::{bool_check, ternary};
use halo2_gadgets::{
    ecc::{
        chip::EccChip, FixedPoint, FixedPointBaseField, NonIdentityPoint, Point, ScalarFixed,
        ScalarVar,
    },
    poseidon::{
        primitives as poseidon, primitives::ConstantLength, Hash as PoseidonHash,
        Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
    },
    sinsemilla::chip::SinsemillaChip,
};
use halo2_proofs::arithmetic::CurveExt;
use halo2_proofs::plonk::{Expression, Constraints};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, Error, Instance},
};
use pasta_curves::{pallas, Ep, IsoEpAffine, Fp, EpAffine};
use proptest::test_runner::Config;

// cm is a point
#[allow(clippy::too_many_arguments)]
pub fn nullifier_circuit(
    mut layouter: impl Layouter<Fp>,
    poseidon_chip: PoseidonChip<Fp, 3, 2>,
    add_chip: AddChip<Fp>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    nk: AssignedCell<Fp, Fp>,
    rho: AssignedCell<Fp, Fp>,
    psi: AssignedCell<Fp, Fp>,
    cm: &Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let poseidon_message = [nk, rho];
    let poseidon_hasher =
        PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
            poseidon_chip,
            layouter.namespace(|| "Poseidon init"),
        )?;
    let hash_nk_rho = poseidon_hasher.hash(
        layouter.namespace(|| "Poseidon_hash(nk, rho)"),
        poseidon_message,
    )?;

    let hash_nk_rho_add_psi = add_chip.add(
        layouter.namespace(|| "scalar = poseidon_hash(nk, rho) + psi"),
        &hash_nk_rho,
        &psi,
    )?;

    // TODO: generate a new generator for nullifier_k
    let nullifier_k = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
    let hash_nk_rho_add_psi_mul_k = nullifier_k.mul(
        layouter.namespace(|| "hash_nk_rho_add_psi * nullifier_k"),
        hash_nk_rho_add_psi,
    )?;

    cm.add(layouter.namespace(|| "nf"), &hash_nk_rho_add_psi_mul_k)
        .map(|res| res.extract_p().inner().clone())
}

// Return variables in the spend note
#[derive(Debug)]
pub struct SpendNoteVar {
    pub user_address: AssignedCell<Fp, Fp>,
    pub app_vp: AssignedCell<Fp, Fp>,
    pub app_data: AssignedCell<Fp, Fp>,
    pub value: AssignedCell<Fp, Fp>,
    pub nf: AssignedCell<Fp, Fp>,
    pub cm: Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
    pub is_normal: AssignedCell<Fp, Fp>,
}

#[allow(clippy::too_many_arguments)]
pub fn check_spend_note(
    mut layouter: impl Layouter<Fp>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    sinsemilla_chip: SinsemillaChip<
        NoteCommitmentHashDomain,
        NoteCommitmentDomain,
        NoteCommitmentFixedBases,
    >,
    note_commit_chip: NoteCommitmentChip,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<Fp, 3, 2>,
    // poseidon_chip: PoseidonChip<Fp, 3, 2>,
    add_chip: AddChip<Fp>,
    spend_note: Note,
    nf_row_idx: usize,
) -> Result<SpendNoteVar, Error> {
    // Check spend note user integrity: user_address = Com_r(Com_r(send_vp, nk), recv_vp_hash)
    let (user_address, nk) = {
        // Witness send_vp
        let send_vp = spend_note
            .user
            .send_com
            .get_send_vp()
            .unwrap()
            .get_compressed();
        let send_vp_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(send_vp),
        )?;

        // Witness nk
        let nk = spend_note.user.get_nk().unwrap();
        let nk_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(nk.inner()),
        )?;

        // send_com = Com_r(send_vp, nk)
        let send_com = {
            let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [send_vp_var, nk_var.clone()];
            poseidon_hasher.hash(layouter.namespace(|| "send_com"), poseidon_message)?
        };

        // Witness recv_vp_hash
        let recv_vp_hash_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(spend_note.user.recv_vp.get_compressed()),
        )?;

        // user_address = Com_r(send_com, recv_vp_hash_var)
        let user_address = {
            let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
            let poseidon_hasher =
                PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    poseidon_chip,
                    layouter.namespace(|| "Poseidon init"),
                )?;
            let poseidon_message = [send_com, recv_vp_hash_var];
            poseidon_hasher.hash(layouter.namespace(|| "user_address"), poseidon_message)?
        };

        (user_address, nk_var)
    };

    // Witness app_vp
    let app_vp = assign_free_advice(
        layouter.namespace(|| "witness app_vp"),
        advices[0],
        Value::known(spend_note.app.get_vp()),
    )?;

    // Witness app_data
    let app_data = assign_free_advice(
        layouter.namespace(|| "witness app_data"),
        advices[0],
        Value::known(spend_note.app.data),
    )?;

    // Witness value(u64)
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(Fp::from(spend_note.value)),
    )?;

    // Witness rho
    let rho = assign_free_advice(
        layouter.namespace(|| "witness rho"),
        advices[0],
        Value::known(spend_note.rho.inner()),
    )?;

    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_spend"),
        advices[0],
        Value::known(spend_note.psi),
    )?;

    // Witness rcm
    let rcm = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "rcm"),
        Value::known(spend_note.rcm),
    )?;

    // Witness is_normal
    let is_normal = assign_free_advice(
        layouter.namespace(|| "witness is_normal"),
        advices[0],
        Value::known(Fp::from(spend_note.is_normal)),
    )?;

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip.clone(),
        note_commit_chip,
        user_address.clone(),
        app_vp.clone(),
        app_data.clone(),
        rho.clone(),
        psi.clone(),
        value.clone(),
        rcm,
        is_normal.clone(),
    )?;

    // Generate nullifier
    let poseidon_chip = PoseidonChip::construct(poseidon_config);
    let nf = nullifier_circuit(
        layouter.namespace(|| "Generate nullifier"),
        poseidon_chip,
        add_chip,
        ecc_chip,
        nk,
        rho,
        psi,
        &cm,
    )?;

    // Public nullifier
    layouter.constrain_instance(nf.cell(), instances, nf_row_idx)?;

    Ok(SpendNoteVar {
        user_address,
        app_vp,
        value,
        app_data,
        nf,
        cm,
        is_normal,
    })
}

// Return variables in the spend note
#[derive(Debug)]
pub struct OutputNoteVar {
    pub user_address: AssignedCell<Fp, Fp>,
    pub app_vp: AssignedCell<Fp, Fp>,
    pub app_data: AssignedCell<Fp, Fp>,
    pub value: AssignedCell<Fp, Fp>,
    pub cm: Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>,
    pub is_normal: AssignedCell<Fp, Fp>,
}

#[allow(clippy::too_many_arguments)]
pub fn check_output_note(
    mut layouter: impl Layouter<Fp>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    sinsemilla_chip: SinsemillaChip<
        NoteCommitmentHashDomain,
        NoteCommitmentDomain,
        NoteCommitmentFixedBases,
    >,
    note_commit_chip: NoteCommitmentChip,
    // PoseidonChip can not be cloned, use PoseidonConfig temporarily
    poseidon_config: PoseidonConfig<Fp, 3, 2>,
    // poseidon_chip: PoseidonChip<Fp, 3, 2>,
    output_note: Note,
    old_nf: AssignedCell<Fp, Fp>,
    cm_row_idx: usize,
) -> Result<OutputNoteVar, Error> {
    // Check output note user integrity: user_address = Com_r(, recv_vp_hash)
    let user_address = {
        let send_com = assign_free_advice(
            layouter.namespace(|| "witness output send_com"),
            advices[0],
            Value::known(output_note.user.send_com.get_closed()),
        )?;
        // Witness recv_vp_hash
        let recv_vp_hash_var = assign_free_advice(
            layouter.namespace(|| "witness nk"),
            advices[0],
            Value::known(output_note.user.recv_vp.get_compressed()),
        )?;

        let poseidon_chip = PoseidonChip::construct(poseidon_config);
        let poseidon_hasher =
            PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                poseidon_chip,
                layouter.namespace(|| "Poseidon init"),
            )?;
        let poseidon_message = [send_com, recv_vp_hash_var];
        poseidon_hasher.hash(layouter.namespace(|| "user_address"), poseidon_message)?
    };

    // Witness app_vp
    let app_vp = assign_free_advice(
        layouter.namespace(|| "witness app_vp"),
        advices[0],
        Value::known(output_note.app.get_vp()),
    )?;

    // Witness app_data
    let app_data = assign_free_advice(
        layouter.namespace(|| "witness app_data"),
        advices[0],
        Value::known(output_note.app.data),
    )?;

    // Witness value(u64)
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(Fp::from(output_note.value)),
    )?;

    // Witness rcm
    let rcm = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "rcm"),
        Value::known(output_note.rcm),
    )?;

    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_output"),
        advices[0],
        Value::known(output_note.psi),
    )?;

    // Witness is_normal
    let is_normal = assign_free_advice(
        layouter.namespace(|| "witness is_normal"),
        advices[0],
        Value::known(Fp::from(output_note.is_normal)),
    )?;

    // Check note commitment
    let cm = note_commitment_gadget(
        layouter.namespace(|| "Hash NoteCommit pieces"),
        sinsemilla_chip,
        ecc_chip,
        note_commit_chip,
        user_address.clone(),
        app_vp.clone(),
        app_data.clone(),
        old_nf,
        psi,
        value.clone(),
        rcm,
        is_normal.clone(),
    )?;

    // Public cm
    let cm_x = cm.extract_p().inner().clone();
    layouter.constrain_instance(cm_x.cell(), instances, cm_row_idx)?;

    Ok(OutputNoteVar {
        user_address,
        app_vp,
        app_data,
        value,
        cm,
        is_normal,
    })
}

// TODO: add hash_to_curve circuit to derivate the value base
pub fn derivate_value_base(
    mut layouter: impl Layouter<Fp>,
    add_config: AddConfig,
    mul_config: MulConfig,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    is_normal: AssignedCell<Fp, Fp>,
    app_vp: AssignedCell<Fp, Fp>,
    app_data: AssignedCell<Fp, Fp>,
) -> Result<NonIdentityPoint<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {

    // hash_to_field out of circuit for now
    let mut us = [Fp::zero(); 2];
    // use pasta_curves::hashtocurve::hash_to_field;
    // hash_to_field::<Fp>(pallas::CURVE_ID, "taiga:test", message, &mut us);
    // TODO hashes to fill us above

    fn get_inverse(
        mut layouter: impl Layouter<Fp>,
        col:Column<Advice>,
        c: AssignedCell<Fp, Fp>
    ) -> AssignedCell<Fp, Fp> {
        assign_free_advice(
            layouter.namespace(|| "inverse"),
            col,
            c.value().map(|x| x.invert().unwrap()),
        ).unwrap()
    }

    fn get_sqrt(
        mut layouter: impl Layouter<Fp>,
        col:Column<Advice>,
        c: AssignedCell<Fp, Fp>
    ) -> AssignedCell<Fp, Fp> {
        assign_free_advice(
            layouter.namespace(|| "sqrt"),
            col,
            c.value().map(|x| x.sqrt()),
        ).unwrap()
    }

    fn map_to_curve_simple_swu_circuit(
        mut layouter: impl Layouter<Fp>,
        u: AssignedCell<Fp, Fp>,
        theta:Fp,
        z: AssignedCell<Fp, Fp>,
        add_config: AddConfig,
        mul_config: MulConfig,
    ) -> Point<EpAffine,EccChip<NoteCommitmentFixedBases>> {
        let add_chip = AddChip::<Fp>::construct(add_config, ());
        let mul_chip = MulChip::<Fp>::construct(mul_config, ());

        let one = Expression::Constant(Fp::one());

        let a = assign_free_advice(
            layouter.namespace(|| "a coefficient of the curve"),
            mul_config.advice[0],
            Value::known(Ep::a()),
        ).unwrap();

        let b = assign_free_advice(
            layouter.namespace(|| "b coefficient of the curve"),
            mul_config.advice[0],
            Value::known(Ep::b()),
        ).unwrap();

        // let a_plus_b = add_chip.add(layouter.namespace(||"aaa"), &a, &b)?;

        let theta = assign_free_advice(
            layouter.namespace(|| "theta"),
            mul_config.advice[0],
            Value::known(Ep::THETA),
        ).unwrap();

        let root_of_unity = assign_free_advice(
            layouter.namespace(|| "root of unity"),
            mul_config.advice[0],
            Value::known(Fp::root_of_unity()),
        ).unwrap();

        let u2: AssignedCell<Fp,Fp> = u*u;
        let z_u2: AssignedCell<Fp,Fp> = z*u2;
        let z_u2_2: AssignedCell<Fp,Fp> = z_u2 * z_u2;
        let ta: AssignedCell<Fp,Fp> = z_u2_2 * z_u2;
        let minus_ta: AssignedCell<Fp,Fp> = -ta;
        let num_x1: AssignedCell<Fp,Fp> = (ta+1)*b;

        // div = a * (ta==0? z : -ta)
        let ta_inv = get_inverse(layouter, mul_config.advice[0], ta);
        
        let ta_eq_zero = bool_check(one.clone() - ta * ta_inv);
        let div: AssignedCell<Fp, Fp> = a * ternary(ta_eq_zero, z, -ta);

        let num2_x1 = num_x1 * num_x1;
        let div2: AssignedCell<Fp,Fp> = div*div;
        let div3: AssignedCell<Fp,Fp> = div2*div;
        let num_gx1: AssignedCell<Fp,Fp> = (num2_x1 + a * div2) * num_x1 + b*div3;
        let num_x2: AssignedCell<Fp,Fp> = num_x1 * z_u2;

        // sqrt ratio part
        let _a = get_inverse(layouter, mul_config.advice[0], div3);
        let _b: AssignedCell<Fp, Fp> = _a * root_of_unity;
        let sqrt_a = get_sqrt(layouter, mul_config.advice[0], _a);
        let sqrt_b = get_sqrt(layouter, mul_config.advice[0], _b);

        let num_gx1_inv = get_inverse(layouter, mul_config.advice[0], num_gx1);
        let num_gx1_eq_zero = bool_check(one.clone() - num_gx1 * num_gx1_inv);

        let div3_eq_zero = bool_check(one.clone() - div3 * _a);

        let tmp: AssignedCell<Fp, Fp> = sqrt_a * sqrt_a - _a;
        let tmp_inv = get_inverse(layouter, mul_config.advice[0], tmp);
        let is_square = bool_check(one.clone() - tmp  *tmp_inv);

        let tmp2: AssignedCell<Fp, Fp> = sqrt_b * sqrt_b - _b;
        let tmp2_inv = get_inverse(layouter, mul_config.advice[0], tmp2);
        let is_nonsquare = bool_check(one.clone() - tmp2*tmp2_inv);
        
        // assert num_gx1_eq_zero | div3_eq_zero | (is_square ^ is_nonsquare)

        let gx1_square: Expression<Fp> = is_square & !(!num_gx1_eq_zero & div3_eq_zero);
        let y1 = ternary(is_square, sqrt_a, sqrt_b);
        let y2: AssignedCell<Fp,Fp> = theta * u * y1 * z_u2;
        
        // TODO idk how to do a condition circuit
        let num_x = ternary(gx1_square, num_x1, num_x2);
        let y = ternary(gx1_square, y1, y2);
        
        let y = if u.is_odd() == y.is_odd() {
            y
        }
        else {
            -y
        };
        // tood public_inputize(num_x *div, y*div3, div)
        Point::from(num_x* div, y*div3, div)
    }

    let q0 = map_to_curve_simple_swu_circuit(
        &mut layouter,
        us[0],
        Ep::THETA,
        Ep::Z,
        add_config,
        mul_config,
    );
    let q1 = map_to_curve_simple_swu_circuit(
        &mut layouter,
        us[1],
        Ep::THETA,
        Ep::Z,
        add_config,
        mul_config,
    );

    let r = ecc_chip.add(
        &mut layouter.namespace(|| "addition q0 + q1"),
        &q0,
        &q1
    ).unwrap();

    //     debug_assert!(bool::from(r.is_on_curve()));

    // iso_map circuit
    let x = r.x();
    let y = r.y();
    let z = r.z();
    // todo is it jacobian??

    let z2: AssignedCell<Fp, Fp> = z * z;
    let z3: AssignedCell<Fp, Fp> = z2 * z;
    let z4: AssignedCell<Fp, Fp> = z2 * z2;
    let z6: AssignedCell<Fp, Fp> = z3 * z3;

    let iso = Ep::ISOGENY_CONSTANTS.iter().map(|coeff| {
        assign_free_advice(
            layouter.namespace(|| "isogeny coefficient"),
            mul_config.advice[0],
            Value::known(coeff),
        ).unwrap()
    }).collect::<AssignedCell<Fp, Fp>>();

    let num_x: AssignedCell<Fp, Fp> = ((iso[0] * x + iso[1] * z2) * x + iso[2] * z4) * x + iso[3] * z6;
    let div_x: AssignedCell<Fp, Fp> = (z2 * x + iso[4] * z4) * x + iso[5] * z6;

    let num_y: AssignedCell<Fp, Fp> = (((iso[6] * x + iso[7] * z2) * x + iso[8] * z4) * x + iso[9] * z6) * y;
    let div_y: AssignedCell<Fp, Fp> = (((x + iso[10] * z2) * x + iso[11] * z4) * x + iso[12] * z6) * z3;

    let zo: AssignedCell<Fp, Fp> = div_x * div_y;
    let xo: AssignedCell<Fp, Fp> = num_x * div_y * zo;
    let yo: AssignedCell<Fp, Fp> = num_y * div_x * zo.square();

    C::new_jacobian(xo, yo, zo).unwrap()

//     hashtocurve::iso_map::<$base, $name, $iso>(&r, &$name::ISOGENY_CONSTANTS)
// })




    let out_of_circuit_value_base = {
        use halo2_proofs::arithmetic::CurveExt;
        let hash = pallas::Point::hash_to_curve("taiga:test");
        let mut bytes: Vec<u8> = vec![];
        is_normal.value().map(|v| bytes.push(v.to_repr()[0]));
        app_vp.value().map(|x| {
            bytes.extend_from_slice(&x.to_repr());
        });
        app_data.value().map(|x| {
            bytes.extend_from_slice(&x.to_repr());
        });
        hash(&bytes)
    };
    NonIdentityPoint::new(
        ecc_chip,
        layouter.namespace(|| "derivate value base"),
        Value::known(out_of_circuit_value_base.to_affine()),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compute_net_value_commitment(
    mut layouter: impl Layouter<Fp>,
    ecc_chip: EccChip<NoteCommitmentFixedBases>,
    is_normal_spend: AssignedCell<Fp, Fp>,
    app_address_spend: AssignedCell<Fp, Fp>,
    data_spend: AssignedCell<Fp, Fp>,
    v_spend: AssignedCell<Fp, Fp>,
    is_normal_output: AssignedCell<Fp, Fp>,
    app_address_output: AssignedCell<Fp, Fp>,
    data_output: AssignedCell<Fp, Fp>,
    v_output: AssignedCell<Fp, Fp>,
    rcv: pallas::Scalar,
) -> Result<Point<pallas::Affine, EccChip<NoteCommitmentFixedBases>>, Error> {
    // spend value point
    let value_base_spend = derivate_value_base(
        layouter.namespace(|| "derivate spend value base"),
        ecc_chip.clone(),
        is_normal_spend,
        app_address_spend,
        data_spend,
    )?;
    let v_spend_scalar = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &v_spend,
    )?;
    let (value_point_spend, _) =
        value_base_spend.mul(layouter.namespace(|| "spend value point"), v_spend_scalar)?;

    // output value point
    let value_base_output = derivate_value_base(
        layouter.namespace(|| "derivate output value base"),
        ecc_chip.clone(),
        is_normal_output,
        app_address_output,
        data_output,
    )?;
    let v_output_scalar = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &v_output,
    )?;
    let (value_point_output, _) =
        value_base_output.mul(layouter.namespace(|| "output value point"), v_output_scalar)?;

    // Get and constrain the negative output value point
    let neg_v_point_output = Point::new(
        ecc_chip.clone(),
        layouter.namespace(|| "negative output value point"),
        value_point_output.inner().point().neg(),
    )?;

    let zero_point = value_point_output.add(
        layouter.namespace(|| "value_point + neg_value_point"),
        &neg_v_point_output,
    )?;
    layouter.assign_region(
        || "constrain zero point",
        |mut region| {
            // Constrain x-coordinates
            region.constrain_constant(zero_point.inner().x().cell(), Fp::zero())?;
            // Constrain y-coordinates
            region.constrain_constant(zero_point.inner().y().cell(), Fp::zero())
        },
    )?;

    let commitment_v = value_point_spend.add(
        layouter.namespace(|| "v_pioint_spend - v_point_output"),
        &neg_v_point_output,
    )?;

    // blind point
    let blind_scalar = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "blind scalar"),
        Value::known(rcv),
    )?;

    let blind_base = FixedPoint::from_inner(ecc_chip, NoteCommitmentFixedBasesFull);
    let (blind, _) = blind_base.mul(
        layouter.namespace(|| "blind_scalar * blind_base"),
        &blind_scalar,
    )?;

    commitment_v.add(layouter.namespace(|| "net value commitment"), &blind)
}

#[test]
fn test_halo2_nullifier_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use crate::circuit::gadgets::AddConfig;
    use crate::constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain,
    };
    use crate::note::NoteCommitment;
    use crate::nullifier::Nullifier;
    use crate::user::NullifierDerivingKey;
    use ff::Field;
    use group::Curve;
    use halo2_gadgets::{
        ecc::chip::EccConfig,
        poseidon::{
            primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
        },
        sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use rand::rngs::OsRng;

    #[derive(Default)]
    struct MyCircuit {
        nk: NullifierDerivingKey,
        rho: Fp,
        psi: Fp,
        cm: NoteCommitment,
    }

    impl Circuit<Fp> for MyCircuit {
        type Config = (
            [Column<Advice>; 10],
            PoseidonConfig<Fp, 3, 2>,
            AddConfig,
            EccConfig<NoteCommitmentFixedBases>,
            // add SinsemillaConfig to load look table, just for test
            SinsemillaConfig<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];

            for advice in advices.iter() {
                meta.enable_equality(*advice);
            }

            let lagrange_coeffs = [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ];

            let table_idx = meta.lookup_table_column();
            let lookup = (
                table_idx,
                meta.lookup_table_column(),
                meta.lookup_table_column(),
            );

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
            let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
                meta,
                advices[6..9].try_into().unwrap(),
                advices[5],
                lagrange_coeffs[2..5].try_into().unwrap(),
                lagrange_coeffs[5..8].try_into().unwrap(),
            );

            let add_config = AddChip::configure(meta, advices[0..2].try_into().unwrap());

            let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
                meta,
                advices,
                lagrange_coeffs,
                range_check,
            );
            let sinsemilla_config = SinsemillaChip::<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[2],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );
            (
                advices,
                poseidon_config,
                add_config,
                ecc_config,
                sinsemilla_config,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let (advices, poseidon_config, add_config, ecc_config, sinsemilla_config) = config;
            let poseidon_chip = PoseidonChip::construct(poseidon_config);
            let ecc_chip = EccChip::construct(ecc_config);
            let add_chip = AddChip::<Fp>::construct(add_config, ());
            SinsemillaChip::<
                NoteCommitmentHashDomain,
                NoteCommitmentDomain,
                NoteCommitmentFixedBases,
            >::load(sinsemilla_config, &mut layouter)?;

            // Witness nk
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                advices[0],
                Value::known(self.nk.inner()),
            )?;

            // Witness rho
            let rho = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                advices[0],
                Value::known(self.rho),
            )?;

            // Witness psi
            let psi = assign_free_advice(
                layouter.namespace(|| "witness psi"),
                advices[0],
                Value::known(self.psi),
            )?;

            // Witness cm
            let cm = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness cm"),
                Value::known(self.cm.inner().to_affine()),
            )?;

            let nf = nullifier_circuit(
                layouter.namespace(|| "nullifier"),
                poseidon_chip,
                add_chip,
                ecc_chip,
                nk,
                rho,
                psi,
                &cm,
            )?;

            let expect_nf = {
                let nf = Nullifier::derive_native(&self.nk, &self.rho, &self.psi, &self.cm).inner();
                assign_free_advice(
                    layouter.namespace(|| "witness nf"),
                    advices[0],
                    Value::known(nf),
                )?
            };

            layouter.assign_region(
                || "constrain result",
                |mut region| region.constrain_equal(nf.cell(), expect_nf.cell()),
            )
        }
    }

    let mut rng = OsRng;
    let circuit = MyCircuit {
        nk: NullifierDerivingKey::rand(&mut rng),
        rho: Fp::random(&mut rng),
        psi: Fp::random(&mut rng),
        cm: NoteCommitment::default(),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
