use crate::circuit::{
    gadgets::{
        assign_free_advice, assign_free_constant, conditional_select::ConditionalSelectConfig,
        poseidon_hash::poseidon_hash_gadget,
    },
    hash_to_curve::{hash_to_curve_circuit, HashToCurveConfig},
    merkle_circuit::{merkle_poseidon_gadget, MerklePoseidonChip},
    resource_commitment::{resource_commit, ResourceCommitChip},
    resource_logic_circuit::{InputResourceVariables, ResourceStatus, ResourceVariables},
};
use crate::constant::{
    TaigaFixedBases, TaigaFixedBasesFull, POSEIDON_TO_CURVE_INPUT_LEN,
    PRF_EXPAND_PERSONALIZATION_TO_FIELD, PRF_EXPAND_PSI, PRF_EXPAND_RCM,
};
use crate::resource::Resource;
use crate::resource_tree::ResourceExistenceWitness;
use crate::utils::poseidon_to_curve;
use halo2_gadgets::{
    ecc::{chip::EccChip, FixedPoint, NonIdentityPoint, Point, ScalarFixed, ScalarVar},
    poseidon::Pow5Config as PoseidonConfig,
    utilities::lookup_range_check::LookupRangeCheckConfig,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, Error, Instance},
};
use pasta_curves::group::Curve;
use pasta_curves::pallas;
use std::ops::Neg;

// cm is a field element
#[allow(clippy::too_many_arguments)]
pub fn nullifier_circuit(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
    nonce: AssignedCell<pallas::Base, pallas::Base>,
    psi: AssignedCell<pallas::Base, pallas::Base>,
    cm: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    let poseidon_message = [nk, nonce, psi, cm];
    poseidon_hash_gadget(
        poseidon_config,
        layouter.namespace(|| "derive nullifier"),
        poseidon_message,
    )
}

// Check input resource integrity and return the input resource variables and the nullifier
#[allow(clippy::too_many_arguments)]
pub fn check_input_resource(
    mut layouter: impl Layouter<pallas::Base>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    resource_commit_chip: ResourceCommitChip,
    input_resource: Resource,
    nf_row_idx: usize,
) -> Result<InputResourceVariables, Error> {
    // Witness nk
    let nk = input_resource.get_nk().unwrap();
    let nk_var = assign_free_advice(
        layouter.namespace(|| "witness nk"),
        advices[0],
        Value::known(nk),
    )?;

    let zero_constant = assign_free_constant(
        layouter.namespace(|| "constant zero"),
        advices[0],
        pallas::Base::zero(),
    )?;

    // npk = Com_r(nk, zero)
    let npk = poseidon_hash_gadget(
        resource_commit_chip.get_poseidon_config(),
        layouter.namespace(|| "npk encoding"),
        [nk_var.clone(), zero_constant],
    )?;

    // Witness value
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(input_resource.value),
    )?;

    // Witness logic
    let logic = assign_free_advice(
        layouter.namespace(|| "witness logic"),
        advices[0],
        Value::known(input_resource.get_logic()),
    )?;

    // Witness label
    let label = assign_free_advice(
        layouter.namespace(|| "witness label"),
        advices[0],
        Value::known(input_resource.get_label()),
    )?;

    // Witness and range check the quantity(u64)
    let quantity = quantity_range_check(
        layouter.namespace(|| "quantity range check"),
        resource_commit_chip.get_lookup_config(),
        input_resource.quantity,
    )?;

    // Witness nonce
    let nonce = assign_free_advice(
        layouter.namespace(|| "witness nonce"),
        advices[0],
        Value::known(input_resource.nonce.inner()),
    )?;

    // Witness rseed
    let rseed = assign_free_advice(
        layouter.namespace(|| "witness rseed"),
        advices[0],
        Value::known(input_resource.rseed),
    )?;

    // We don't need the constraints on psi and rcm derivation for input resource.
    // If the psi and rcm are not correct, the existence checking would fail.
    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_input"),
        advices[0],
        Value::known(input_resource.get_psi()),
    )?;

    // Witness rcm
    let rcm = assign_free_advice(
        layouter.namespace(|| "witness rcm"),
        advices[0],
        Value::known(input_resource.get_rcm()),
    )?;

    // Witness is_ephemeral
    // is_ephemeral will be boolean-constrained in the resource_commit.
    let is_ephemeral = assign_free_advice(
        layouter.namespace(|| "witness is_ephemeral"),
        advices[0],
        Value::known(pallas::Base::from(input_resource.is_ephemeral)),
    )?;

    // Check resource commitment
    let cm = resource_commit(
        layouter.namespace(|| "resource commitment"),
        resource_commit_chip.clone(),
        logic.clone(),
        label.clone(),
        value.clone(),
        npk.clone(),
        nonce.clone(),
        psi.clone(),
        quantity.clone(),
        is_ephemeral.clone(),
        rcm.clone(),
    )?;

    // Generate nullifier
    let nf = nullifier_circuit(
        layouter.namespace(|| "Generate nullifier"),
        resource_commit_chip.get_poseidon_config(),
        nk_var,
        nonce.clone(),
        psi.clone(),
        cm.clone(),
    )?;

    // Public nullifier
    layouter.constrain_instance(nf.cell(), instances, nf_row_idx)?;

    let resource_variables = ResourceVariables {
        logic,
        quantity,
        label,
        is_ephemeral,
        value,
        nonce,
        npk,
        rseed,
    };

    Ok(InputResourceVariables {
        resource_variables,
        nf,
        cm,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn check_output_resource(
    mut layouter: impl Layouter<pallas::Base>,
    advices: [Column<Advice>; 10],
    instances: Column<Instance>,
    resource_commit_chip: ResourceCommitChip,
    output_resource: Resource,
    old_nf: AssignedCell<pallas::Base, pallas::Base>,
    cm_row_idx: usize,
) -> Result<ResourceVariables, Error> {
    // Witness npk
    let npk = assign_free_advice(
        layouter.namespace(|| "witness npk"),
        advices[0],
        Value::known(output_resource.get_npk()),
    )?;

    // Witness value
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(output_resource.value),
    )?;

    // Witness logic
    let logic = assign_free_advice(
        layouter.namespace(|| "witness logic"),
        advices[0],
        Value::known(output_resource.get_logic()),
    )?;

    // Witness label
    let label = assign_free_advice(
        layouter.namespace(|| "witness label"),
        advices[0],
        Value::known(output_resource.get_label()),
    )?;

    // Witness and range check the quantity(u64)
    let quantity = quantity_range_check(
        layouter.namespace(|| "quantity range check"),
        resource_commit_chip.get_lookup_config(),
        output_resource.quantity,
    )?;

    // Witness rseed
    let rseed = assign_free_advice(
        layouter.namespace(|| "witness rseed"),
        advices[0],
        Value::known(output_resource.rseed),
    )?;

    // Witness rcm
    let prf_expand_personalization = assign_free_constant(
        layouter.namespace(|| "constant PRF_EXPAND_PERSONALIZATION_TO_FIELD"),
        advices[0],
        *PRF_EXPAND_PERSONALIZATION_TO_FIELD,
    )?;
    let rcm_message = {
        let prf_expand_rcm = assign_free_constant(
            layouter.namespace(|| "constant PRF_EXPAND_RCM"),
            advices[0],
            pallas::Base::from(PRF_EXPAND_RCM as u64),
        )?;
        [
            prf_expand_personalization.clone(),
            prf_expand_rcm,
            rseed.clone(),
            old_nf.clone(),
        ]
    };
    let rcm = poseidon_hash_gadget(
        resource_commit_chip.get_poseidon_config(),
        layouter.namespace(|| "derive the rcm"),
        rcm_message,
    )?;

    // Witness psi
    let psi_message = {
        let prf_expand_psi = assign_free_constant(
            layouter.namespace(|| "constant PRF_EXPAND_PSI"),
            advices[0],
            pallas::Base::from(PRF_EXPAND_PSI as u64),
        )?;
        [
            prf_expand_personalization,
            prf_expand_psi,
            rseed.clone(),
            old_nf.clone(),
        ]
    };
    let psi = poseidon_hash_gadget(
        resource_commit_chip.get_poseidon_config(),
        layouter.namespace(|| "derive the psi"),
        psi_message,
    )?;

    // Witness is_ephemeral
    // is_ephemeral will be boolean-constrained in the resource_commit.
    let is_ephemeral = assign_free_advice(
        layouter.namespace(|| "witness is_ephemeral"),
        advices[0],
        Value::known(pallas::Base::from(output_resource.is_ephemeral)),
    )?;

    // Check resource commitment
    let cm = resource_commit(
        layouter.namespace(|| "resource commitment"),
        resource_commit_chip,
        logic.clone(),
        label.clone(),
        value.clone(),
        npk.clone(),
        old_nf.clone(),
        psi.clone(),
        quantity.clone(),
        is_ephemeral.clone(),
        rcm.clone(),
    )?;

    // Public cm
    layouter.constrain_instance(cm.cell(), instances, cm_row_idx)?;

    Ok(ResourceVariables {
        logic,
        label,
        quantity,
        is_ephemeral,
        value,
        nonce: old_nf,
        npk,
        rseed,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn load_resource(
    mut layouter: impl Layouter<pallas::Base>,
    advices: [Column<Advice>; 10],
    resource_commit_chip: ResourceCommitChip,
    conditional_select_config: ConditionalSelectConfig,
    merkle_chip: MerklePoseidonChip,
    resource_witness: &ResourceExistenceWitness,
) -> Result<ResourceStatus, Error> {
    let resource = resource_witness.get_resource();
    let merkle_path = resource_witness.get_path();
    let is_input = resource_witness.is_input();

    // Witness is_input
    let is_input_var = assign_free_advice(
        layouter.namespace(|| "witness is_input"),
        advices[0],
        Value::known(pallas::Base::from(is_input)),
    )?;

    // Witness nk or npk
    let nk_or_npk = if is_input {
        resource.get_nk().unwrap()
    } else {
        resource.get_npk()
    };

    let nk_or_npk_var = assign_free_advice(
        layouter.namespace(|| "witness nk_or_npk"),
        advices[0],
        Value::known(nk_or_npk),
    )?;

    let zero_constant = assign_free_constant(
        layouter.namespace(|| "constant zero"),
        advices[0],
        pallas::Base::zero(),
    )?;

    // npk = Com_r(nk, zero)
    let input_npk = poseidon_hash_gadget(
        resource_commit_chip.get_poseidon_config(),
        layouter.namespace(|| "npk encoding"),
        [nk_or_npk_var.clone(), zero_constant],
    )?;

    let npk = layouter.assign_region(
        || "conditional select: npk",
        |mut region| {
            conditional_select_config.assign_region(
                &is_input_var,
                &input_npk,
                &nk_or_npk_var,
                0,
                &mut region,
            )
        },
    )?;

    // Witness value
    let value = assign_free_advice(
        layouter.namespace(|| "witness value"),
        advices[0],
        Value::known(resource.value),
    )?;

    // Witness logic
    let logic = assign_free_advice(
        layouter.namespace(|| "witness logic"),
        advices[0],
        Value::known(resource.get_logic()),
    )?;

    // Witness label
    let label = assign_free_advice(
        layouter.namespace(|| "witness label"),
        advices[0],
        Value::known(resource.get_label()),
    )?;

    // Witness and range check the quantity(u64)
    let quantity = quantity_range_check(
        layouter.namespace(|| "quantity range check"),
        resource_commit_chip.get_lookup_config(),
        resource.quantity,
    )?;

    // Witness nonce
    let nonce = assign_free_advice(
        layouter.namespace(|| "witness nonce"),
        advices[0],
        Value::known(resource.nonce.inner()),
    )?;

    // Witness rseed
    let rseed = assign_free_advice(
        layouter.namespace(|| "witness rseed"),
        advices[0],
        Value::known(resource.rseed),
    )?;

    // We don't need the constraints on psi and rcm derivation for input resource.
    // If the psi and rcm are not correct, the existence checking would fail.
    // Witness psi
    let psi = assign_free_advice(
        layouter.namespace(|| "witness psi_input"),
        advices[0],
        Value::known(resource.get_psi()),
    )?;

    // Witness rcm
    let rcm = assign_free_advice(
        layouter.namespace(|| "witness rcm"),
        advices[0],
        Value::known(resource.get_rcm()),
    )?;

    // Witness is_ephemeral
    // is_ephemeral will be boolean-constrained in the resource_commit.
    let is_ephemeral = assign_free_advice(
        layouter.namespace(|| "witness is_ephemeral"),
        advices[0],
        Value::known(pallas::Base::from(resource.is_ephemeral)),
    )?;

    // Check resource commitment
    let cm = resource_commit(
        layouter.namespace(|| "resource commitment"),
        resource_commit_chip.clone(),
        logic.clone(),
        label.clone(),
        value.clone(),
        npk.clone(),
        nonce.clone(),
        psi.clone(),
        quantity.clone(),
        is_ephemeral.clone(),
        rcm.clone(),
    )?;

    // Generate the nullifier if the resource is an input
    let nf = nullifier_circuit(
        layouter.namespace(|| "Generate nullifier"),
        resource_commit_chip.get_poseidon_config(),
        nk_or_npk_var,
        nonce.clone(),
        psi.clone(),
        cm.clone(),
    )?;

    // The self_id is the nullifier if the resource is an input, otherwise it's
    // the commitment
    let self_id = layouter.assign_region(
        || "conditional select: nullifier or commitment",
        |mut region| {
            conditional_select_config.assign_region(&is_input_var, &nf, &cm, 0, &mut region)
        },
    )?;

    // Check resource existence(merkle path)
    // TODO: constrain the first LR(is_input)
    let root = merkle_poseidon_gadget(
        layouter.namespace(|| "poseidon merkle"),
        merkle_chip,
        self_id.clone(),
        &merkle_path,
    )?;

    let resource_variables = ResourceVariables {
        logic,
        quantity,
        label,
        is_ephemeral,
        value,
        nonce,
        npk,
        rseed,
    };

    Ok(ResourceStatus {
        resource_merkle_root: root,
        is_input: is_input_var,
        identity: self_id,
        resource: resource_variables,
    })
}

pub fn derive_kind(
    mut layouter: impl Layouter<pallas::Base>,
    hash_to_curve_config: HashToCurveConfig,
    ecc_chip: EccChip<TaigaFixedBases>,
    logic: AssignedCell<pallas::Base, pallas::Base>,
    label: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<NonIdentityPoint<pallas::Affine, EccChip<TaigaFixedBases>>, Error> {
    let point = hash_to_curve_circuit(
        layouter.namespace(|| "hash to curve"),
        hash_to_curve_config,
        ecc_chip.clone(),
        &[logic.clone(), label.clone()],
    )?;

    // Assign a new `NonIdentityPoint` and constran equal to hash_to_curve point since `Point` doesn't have mul operation
    // IndentityPoint is an invalid resource kind and it returns an error.
    let non_identity_point = logic.value().zip(label.value()).map(|(&vk, &data)| {
        poseidon_to_curve::<POSEIDON_TO_CURVE_INPUT_LEN>(&[vk, data]).to_affine()
    });
    let non_identity_point_var = NonIdentityPoint::new(
        ecc_chip,
        layouter.namespace(|| "non-identity resource kind"),
        non_identity_point,
    )?;
    point.constrain_equal(
        layouter.namespace(|| "non-identity resource kind"),
        &non_identity_point_var,
    )?;
    Ok(non_identity_point_var)
}

#[allow(clippy::too_many_arguments)]
pub fn compute_delta_commitment(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip<TaigaFixedBases>,
    hash_to_curve_config: HashToCurveConfig,
    input_logic: AssignedCell<pallas::Base, pallas::Base>,
    input_label: AssignedCell<pallas::Base, pallas::Base>,
    input_quantity: AssignedCell<pallas::Base, pallas::Base>,
    output_logic: AssignedCell<pallas::Base, pallas::Base>,
    output_label: AssignedCell<pallas::Base, pallas::Base>,
    output_quantity: AssignedCell<pallas::Base, pallas::Base>,
    rcv: pallas::Scalar,
) -> Result<Point<pallas::Affine, EccChip<TaigaFixedBases>>, Error> {
    // input value base point
    let input_kind = derive_kind(
        layouter.namespace(|| "derive input resource kind"),
        hash_to_curve_config.clone(),
        ecc_chip.clone(),
        input_logic,
        input_label,
    )?;
    let v_input_scalar = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &input_quantity,
    )?;
    let (value_point_input, _) =
        input_kind.mul(layouter.namespace(|| "input value point"), v_input_scalar)?;

    // output value base point
    let output_kind = derive_kind(
        layouter.namespace(|| "derive output resource kind"),
        hash_to_curve_config,
        ecc_chip.clone(),
        output_logic,
        output_label,
    )?;
    let v_output_scalar = ScalarVar::from_base(
        ecc_chip.clone(),
        layouter.namespace(|| "ScalarVar from_base"),
        &output_quantity,
    )?;
    let (value_point_output, _) =
        output_kind.mul(layouter.namespace(|| "output value point"), v_output_scalar)?;

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
            region.constrain_constant(zero_point.inner().x().cell(), pallas::Base::zero())?;
            // Constrain y-coordinates
            region.constrain_constant(zero_point.inner().y().cell(), pallas::Base::zero())
        },
    )?;

    let commitment_v = value_point_input.add(
        layouter.namespace(|| "v_pioint_input - v_point_output"),
        &neg_v_point_output,
    )?;

    // blind point
    let blind_scalar = ScalarFixed::new(
        ecc_chip.clone(),
        layouter.namespace(|| "blind scalar"),
        Value::known(rcv),
    )?;

    let blind_base = FixedPoint::from_inner(ecc_chip, TaigaFixedBasesFull::ResourceCommitmentR);
    let (blind, _) = blind_base.mul(
        layouter.namespace(|| "blind_scalar * blind_base"),
        &blind_scalar,
    )?;

    commitment_v.add(layouter.namespace(|| "delta commitment"), &blind)
}

fn quantity_range_check<const K: usize>(
    mut layouter: impl Layouter<pallas::Base>,
    lookup_config: &LookupRangeCheckConfig<pallas::Base, K>,
    quantity: u64,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    let zs = lookup_config.witness_check(
        layouter.namespace(|| "6 * K(10) bits range check"),
        Value::known(pallas::Base::from(quantity)),
        6,
        false,
    )?;

    lookup_config.copy_short_check(
        layouter.namespace(|| "4 bits range check"),
        zs[6].clone(),
        4,
    )?;

    Ok(zs[0].clone())
}

#[test]
fn test_halo2_nullifier_circuit() {
    use crate::circuit::gadgets::assign_free_advice;
    use crate::nullifier::{Nullifier, NullifierKeyContainer};
    use crate::resource::ResourceCommitment;
    use halo2_gadgets::poseidon::{
        primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
    };
    use halo2_proofs::{
        arithmetic::Field,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use rand::rngs::OsRng;

    #[derive(Default)]
    struct MyCircuit {
        nk: NullifierKeyContainer,
        nonce: pallas::Base,
        psi: pallas::Base,
        cm: ResourceCommitment,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        #[allow(clippy::type_complexity)]
        type Config = ([Column<Advice>; 10], PoseidonConfig<pallas::Base, 3, 2>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
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

            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
                meta,
                advices[6..9].try_into().unwrap(),
                advices[5],
                lagrange_coeffs[2..5].try_into().unwrap(),
                lagrange_coeffs[5..8].try_into().unwrap(),
            );
            (advices, poseidon_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let (advices, poseidon_config) = config;
            // Witness nk
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                advices[0],
                Value::known(self.nk.get_nk().unwrap()),
            )?;

            // Witness nonce
            let nonce = assign_free_advice(
                layouter.namespace(|| "witness nonce"),
                advices[0],
                Value::known(self.nonce),
            )?;

            // Witness psi
            let psi = assign_free_advice(
                layouter.namespace(|| "witness psi"),
                advices[0],
                Value::known(self.psi),
            )?;

            // Witness cm
            let cm = assign_free_advice(
                layouter.namespace(|| "witness cm"),
                advices[0],
                Value::known(self.cm.inner()),
            )?;

            let nf = nullifier_circuit(
                layouter.namespace(|| "nullifier"),
                poseidon_config,
                nk,
                nonce,
                psi,
                cm,
            )?;

            let expect_nf = {
                let nf = Nullifier::derive(&self.nk, &self.nonce, &self.psi, &self.cm)
                    .unwrap()
                    .inner();
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
        nk: NullifierKeyContainer::random_key(&mut rng),
        nonce: pallas::Base::random(&mut rng),
        psi: pallas::Base::random(&mut rng),
        cm: ResourceCommitment::default(),
    };

    let prover = MockProver::run(11, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()))
}
