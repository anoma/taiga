use crate::circuit::blake2s::{vp_commitment_gadget, Blake2sChip, Blake2sConfig};
use crate::circuit::gadgets::assign_free_advice;
use crate::circuit::hash_to_curve::HashToCurveConfig;
use crate::circuit::integrity::{
    check_input_resource, check_output_resource, compute_value_commitment,
};
use crate::circuit::merkle_circuit::{
    merkle_poseidon_gadget, MerklePoseidonChip, MerklePoseidonConfig,
};
use crate::constant::{
    TaigaFixedBases, ACTION_ANCHOR_PUBLIC_INPUT_ROW_IDX, ACTION_INPUT_VP_CM_1_ROW_IDX,
    ACTION_INPUT_VP_CM_2_ROW_IDX, ACTION_NET_VALUE_CM_X_PUBLIC_INPUT_ROW_IDX,
    ACTION_NET_VALUE_CM_Y_PUBLIC_INPUT_ROW_IDX, ACTION_NF_PUBLIC_INPUT_ROW_IDX,
    ACTION_OUTPUT_CM_PUBLIC_INPUT_ROW_IDX, ACTION_OUTPUT_VP_CM_1_ROW_IDX,
    ACTION_OUTPUT_VP_CM_2_ROW_IDX, TAIGA_COMMITMENT_TREE_DEPTH,
};
use crate::merkle_tree::LR;
use crate::resource::Resource;

use halo2_gadgets::{
    ecc::chip::{EccChip, EccConfig},
    poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig},
    utilities::lookup_range_check::LookupRangeCheckConfig,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Instance, Selector,
        TableColumn,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

use crate::circuit::resource_commitment::{ResourceCommitChip, ResourceCommitConfig};

#[derive(Clone, Debug)]
pub struct ActionConfig {
    instances: Column<Instance>,
    advices: [Column<Advice>; 10],
    table_idx: TableColumn,
    ecc_config: EccConfig<TaigaFixedBases>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    merkle_config: MerklePoseidonConfig,
    merkle_path_selector: Selector,
    hash_to_curve_config: HashToCurveConfig,
    blake2s_config: Blake2sConfig<pallas::Base>,
    resource_commit_config: ResourceCommitConfig,
}

/// The Action circuit.
#[derive(Clone, Debug, Default)]
pub struct ActionCircuit {
    /// Input resource
    pub input_resource: Resource,
    /// The authorization path of input resource
    pub merkle_path: [(pallas::Base, LR); TAIGA_COMMITMENT_TREE_DEPTH],
    /// Output resource
    pub output_resource: Resource,
    /// random scalar for net value commitment
    pub rcv: pallas::Scalar,
    /// The randomness for input resource application vp commitment
    pub input_vp_cm_r: pallas::Base,
    /// The randomness for output resource application vp commitment
    pub output_vp_cm_r: pallas::Base,
}

impl Circuit<pallas::Base> for ActionCircuit {
    type Config = ActionConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let instances = meta.instance_column();
        meta.enable_equality(instances);

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

        let table_idx = meta.lookup_table_column();

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

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
        meta.enable_constant(lagrange_coeffs[0]);

        let ecc_config =
            EccChip::<TaigaFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            lagrange_coeffs[2..5].try_into().unwrap(),
            lagrange_coeffs[5..8].try_into().unwrap(),
        );

        let merkle_path_selector = meta.selector();
        meta.create_gate("merkle path check", |meta| {
            let merkle_path_selector = meta.query_selector(merkle_path_selector);
            let is_merkle_checked_input = meta.query_advice(advices[0], Rotation::cur());
            let anchor = meta.query_advice(advices[1], Rotation::cur());
            let root = meta.query_advice(advices[2], Rotation::cur());

            Constraints::with_selector(
                merkle_path_selector,
                [(
                    "is_merkle_checked is false, or root = anchor",
                    is_merkle_checked_input * (root - anchor),
                )],
            )
        });

        let merkle_config = MerklePoseidonChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            poseidon_config.clone(),
        );

        let hash_to_curve_config =
            HashToCurveConfig::configure(meta, advices, poseidon_config.clone());

        let blake2s_config = Blake2sConfig::configure(meta, advices);

        let resource_commit_config = ResourceCommitChip::configure(
            meta,
            advices[0..3].try_into().unwrap(),
            poseidon_config.clone(),
            range_check,
        );

        Self::Config {
            instances,
            advices,
            table_idx,
            ecc_config,
            poseidon_config,
            merkle_config,
            merkle_path_selector,
            hash_to_curve_config,
            blake2s_config,
            resource_commit_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);
        layouter.assign_table(
            || "table_idx",
            |mut table| {
                // We generate the row values lazily (we only need them during keygen).
                for index in 0..(1 << 10) {
                    table.assign_cell(
                        || "table_idx",
                        config.table_idx,
                        index,
                        || Value::known(pallas::Base::from(index as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        // Construct a merkle chip
        let merkle_chip = MerklePoseidonChip::construct(config.merkle_config);

        // Construct a blake2s chip
        let blake2s_chip = Blake2sChip::construct(config.blake2s_config);

        // Construct a resource_commit chip
        let resource_commit_chip = ResourceCommitChip::construct(config.resource_commit_config);

        // Input resource
        // Check the input resource commitment
        let input_resource_variables = check_input_resource(
            layouter.namespace(|| "check input resource"),
            config.advices,
            config.instances,
            resource_commit_chip.clone(),
            self.input_resource,
            ACTION_NF_PUBLIC_INPUT_ROW_IDX,
        )?;

        // Check the merkle tree path validity and public the root
        let root = merkle_poseidon_gadget(
            layouter.namespace(|| "poseidon merkle"),
            merkle_chip,
            input_resource_variables.cm,
            &self.merkle_path,
        )?;

        // Output resource
        let output_resource_vars = check_output_resource(
            layouter.namespace(|| "check output resource"),
            config.advices,
            config.instances,
            resource_commit_chip,
            self.output_resource,
            input_resource_variables.nf,
            ACTION_OUTPUT_CM_PUBLIC_INPUT_ROW_IDX,
        )?;

        // compute and public net value commitment(input_value_commitment - output_value_commitment)
        let cv_net = compute_value_commitment(
            layouter.namespace(|| "net value commitment"),
            ecc_chip,
            config.hash_to_curve_config.clone(),
            input_resource_variables.resource_variables.app_vk.clone(),
            input_resource_variables
                .resource_variables
                .app_data_static
                .clone(),
            input_resource_variables.resource_variables.quantity.clone(),
            output_resource_vars.resource_variables.app_vk.clone(),
            output_resource_vars
                .resource_variables
                .app_data_static
                .clone(),
            output_resource_vars.resource_variables.quantity,
            self.rcv,
        )?;
        layouter.constrain_instance(
            cv_net.inner().x().cell(),
            config.instances,
            ACTION_NET_VALUE_CM_X_PUBLIC_INPUT_ROW_IDX,
        )?;
        layouter.constrain_instance(
            cv_net.inner().y().cell(),
            config.instances,
            ACTION_NET_VALUE_CM_Y_PUBLIC_INPUT_ROW_IDX,
        )?;

        // merkle path check
        layouter.assign_region(
            || "merkle path check",
            |mut region| {
                input_resource_variables
                    .resource_variables
                    .is_merkle_checked
                    .copy_advice(
                        || "is_merkle_checked_input",
                        &mut region,
                        config.advices[0],
                        0,
                    )?;
                region.assign_advice_from_instance(
                    || "anchor",
                    config.instances,
                    ACTION_ANCHOR_PUBLIC_INPUT_ROW_IDX,
                    config.advices[1],
                    0,
                )?;
                root.copy_advice(|| "root", &mut region, config.advices[2], 0)?;
                config.merkle_path_selector.enable(&mut region, 0)
            },
        )?;

        // Input resource application VP commitment
        let input_vp_cm_r = assign_free_advice(
            layouter.namespace(|| "witness input_vp_cm_r"),
            config.advices[0],
            Value::known(self.input_vp_cm_r),
        )?;
        let input_vp_commitment = vp_commitment_gadget(
            &mut layouter,
            &blake2s_chip,
            input_resource_variables.resource_variables.app_vk.clone(),
            input_vp_cm_r,
        )?;
        layouter.constrain_instance(
            input_vp_commitment[0].cell(),
            config.instances,
            ACTION_INPUT_VP_CM_1_ROW_IDX,
        )?;
        layouter.constrain_instance(
            input_vp_commitment[1].cell(),
            config.instances,
            ACTION_INPUT_VP_CM_2_ROW_IDX,
        )?;

        // Output resource application VP commitment
        let output_vp_cm_r = assign_free_advice(
            layouter.namespace(|| "witness output_vp_cm_r"),
            config.advices[0],
            Value::known(self.output_vp_cm_r),
        )?;
        let output_vp_commitment = vp_commitment_gadget(
            &mut layouter,
            &blake2s_chip,
            output_resource_vars.resource_variables.app_vk.clone(),
            output_vp_cm_r,
        )?;
        layouter.constrain_instance(
            output_vp_commitment[0].cell(),
            config.instances,
            ACTION_OUTPUT_VP_CM_1_ROW_IDX,
        )?;
        layouter.constrain_instance(
            output_vp_commitment[1].cell(),
            config.instances,
            ACTION_OUTPUT_VP_CM_2_ROW_IDX,
        )?;

        Ok(())
    }
}

#[test]
fn test_halo2_action_circuit() {
    use crate::action::tests::random_action_info;
    use crate::constant::{
        ACTION_CIRCUIT_PARAMS_SIZE, ACTION_PROVING_KEY, ACTION_VERIFYING_KEY, SETUP_PARAMS_MAP,
    };
    use crate::proof::Proof;
    use halo2_proofs::dev::MockProver;

    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let action_info = random_action_info(&mut rng);
    let (action, action_circuit) = action_info.build();
    let instances = vec![action.to_instance()];
    let prover =
        MockProver::<pallas::Base>::run(ACTION_CIRCUIT_PARAMS_SIZE, &action_circuit, instances)
            .unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // Create action proof
    let params = SETUP_PARAMS_MAP.get(&ACTION_CIRCUIT_PARAMS_SIZE).unwrap();
    let proof = Proof::create(
        &ACTION_PROVING_KEY,
        params,
        action_circuit,
        &[&action.to_instance()],
        &mut rng,
    )
    .unwrap();

    assert!(proof
        .verify(&ACTION_VERIFYING_KEY, params, &[&action.to_instance()])
        .is_ok());
}
