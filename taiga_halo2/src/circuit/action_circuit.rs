use crate::circuit::gadgets::AddChip;
use crate::circuit::integrity::{
    check_output_note, check_spend_note, compute_net_value_commitment,
};
use crate::circuit::merkle_circuit::{
    merkle_poseidon_gadget, MerklePoseidonChip, MerklePoseidonConfig,
};
use crate::circuit::note_circuit::{NoteChip, NoteCommitmentChip, NoteConfig};
use crate::constant::{
    NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain,
    ACTION_ANCHOR_INSTANCE_ROW_IDX, ACTION_ENABLE_INPUT_INSTANCE_ROW_IDX,
    ACTION_ENABLE_OUTPUT_INSTANCE_ROW_IDX, ACTION_NET_VALUE_CM_X_INSTANCE_ROW_IDX,
    ACTION_NET_VALUE_CM_Y_INSTANCE_ROW_IDX, ACTION_NF_INSTANCE_ROW_IDX,
    ACTION_OUTPUT_CM_INSTANCE_ROW_IDX, TAIGA_COMMITMENT_TREE_DEPTH,
};
use crate::note::Note;
use halo2_gadgets::{ecc::chip::EccChip, sinsemilla::chip::SinsemillaChip, utilities::bool_check};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

#[derive(Clone, Debug)]
pub struct ActionConfig {
    instances: Column<Instance>,
    advices: [Column<Advice>; 10],
    note_config: NoteConfig,
    merkle_config: MerklePoseidonConfig,
    basic_checks_selector: Selector,
}

/// The Action circuit.
#[derive(Clone, Debug, Default)]
pub struct ActionCircuit {
    /// Spent note
    pub spend_note: Note,
    /// The authorization path of spend note
    pub auth_path: [(pallas::Base, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    /// Output note
    pub output_note: Note,
    /// random scalar for net value commitment
    pub rcv: pallas::Scalar,
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

        let basic_checks_selector = meta.selector();
        meta.create_gate("Basic checks", |meta| {
            let basic_checks_selector = meta.query_selector(basic_checks_selector);
            let is_normal_input = meta.query_advice(advices[0], Rotation::cur());
            let is_normal_output = meta.query_advice(advices[1], Rotation::cur());
            let v_input = meta.query_advice(advices[2], Rotation::cur());
            let v_output = meta.query_advice(advices[3], Rotation::cur());

            let anchor = meta.query_advice(advices[4], Rotation::cur());
            let root = meta.query_advice(advices[5], Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());

            // if v_normal = 0, it's a dummy note.
            let v_normal_input = v_input * is_normal_input;
            let v_normal_output = v_output * is_normal_output;

            // `v_normal` zero check.
            // Constrain: v_normal(1 - v_normal * v_normal_inv) = 0, in which is_zero = (1 - v_normal * v_normal_inv)
            let v_normal_input_inv = meta.query_advice(advices[6], Rotation::cur());
            let is_dummy_input = one.clone() - v_normal_input.clone() * v_normal_input_inv;
            let v_normal_output_inv = meta.query_advice(advices[7], Rotation::cur());
            let is_dummy_output = one.clone() - v_normal_output.clone() * v_normal_output_inv;

            let enable_input = meta.query_advice(advices[8], Rotation::cur());
            let enable_output = meta.query_advice(advices[9], Rotation::cur());

            Constraints::with_selector(
                basic_checks_selector,
                [
                    (
                        "dummy input, or root = anchor",
                        v_normal_input.clone() * (root - anchor),
                    ),
                    (
                        "v_normal_input zero check",
                        v_normal_input * is_dummy_input.clone(),
                    ),
                    ("bool check enable_input", bool_check(enable_input.clone())),
                    (
                        "check enable input: not relation",
                        is_dummy_input + enable_input - one.clone(),
                    ),
                    (
                        "v_normal_output zero check",
                        v_normal_output * is_dummy_output.clone(),
                    ),
                    (
                        "bool check enable_output",
                        bool_check(enable_output.clone()),
                    ),
                    (
                        "check enable output: not relation",
                        is_dummy_output + enable_output - one,
                    ),
                ],
            )
        });

        let note_config = NoteChip::configure(meta, instances, advices);

        let merkle_config = MerklePoseidonChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            note_config.poseidon_config.clone(),
        );

        Self::Config {
            instances,
            advices,
            note_config,
            merkle_config,
            basic_checks_selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::<
            NoteCommitmentHashDomain,
            NoteCommitmentDomain,
            NoteCommitmentFixedBases,
        >::load(config.note_config.sinsemilla_config.clone(), &mut layouter)?;

        // Construct a Sinsemilla chip
        let sinsemilla_chip =
            SinsemillaChip::construct(config.note_config.sinsemilla_config.clone());

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.note_config.ecc_config);

        // Construct a NoteCommit chip
        let note_commit_chip =
            NoteCommitmentChip::construct(config.note_config.note_commit_config.clone());

        // Construct an add chip
        let add_chip = AddChip::<pallas::Base>::construct(config.note_config.add_config, ());

        // Construct a merkle chip
        let merkle_chip = MerklePoseidonChip::construct(config.merkle_config);

        // Spend note
        // Check the spend note commitment
        let spend_note_vars = check_spend_note(
            layouter.namespace(|| "check spend note"),
            config.advices,
            config.instances,
            ecc_chip.clone(),
            sinsemilla_chip.clone(),
            note_commit_chip.clone(),
            config.note_config.poseidon_config.clone(),
            add_chip,
            self.spend_note.clone(),
            ACTION_NF_INSTANCE_ROW_IDX,
        )?;

        // Check the merkle tree path validity and public the root
        let leaf = spend_note_vars.cm.extract_p().inner().clone();
        let root = merkle_poseidon_gadget(
            layouter.namespace(|| "poseidon merkle"),
            merkle_chip,
            leaf,
            &self.auth_path,
        )?;

        // TODO: user send address VP commitment and app VP commitment

        // Output note
        let output_note_vars = check_output_note(
            layouter.namespace(|| "check output note"),
            config.advices,
            config.instances,
            ecc_chip.clone(),
            sinsemilla_chip,
            note_commit_chip,
            config.note_config.poseidon_config,
            self.output_note.clone(),
            spend_note_vars.nf,
            ACTION_OUTPUT_CM_INSTANCE_ROW_IDX,
        )?;

        // TODO: add user receive address VP commitment and app VP commitment

        // TODO: add note verifiable encryption

        // compute and public net value commitment(input_value_commitment - output_value_commitment)
        let net_value_commitment = compute_net_value_commitment(
            layouter.namespace(|| "net value commitment"),
            ecc_chip,
            spend_note_vars.is_normal.clone(),
            spend_note_vars.app_address.clone(),
            spend_note_vars.data.clone(),
            spend_note_vars.value.clone(),
            output_note_vars.is_normal.clone(),
            output_note_vars.app_address.clone(),
            output_note_vars.data.clone(),
            output_note_vars.value.clone(),
            self.rcv,
        )?;
        layouter.constrain_instance(
            net_value_commitment.inner().x().cell(),
            config.instances,
            ACTION_NET_VALUE_CM_X_INSTANCE_ROW_IDX,
        )?;
        layouter.constrain_instance(
            net_value_commitment.inner().y().cell(),
            config.instances,
            ACTION_NET_VALUE_CM_Y_INSTANCE_ROW_IDX,
        )?;

        // Basic checks
        layouter.assign_region(
            || "Basic checks",
            |mut region| {
                spend_note_vars.is_normal.copy_advice(
                    || "is_normal_input",
                    &mut region,
                    config.advices[0],
                    0,
                )?;
                output_note_vars.is_normal.copy_advice(
                    || "is_normal_output",
                    &mut region,
                    config.advices[1],
                    0,
                )?;
                spend_note_vars.value.copy_advice(
                    || "v_input",
                    &mut region,
                    config.advices[2],
                    0,
                )?;
                output_note_vars.value.copy_advice(
                    || "v_output",
                    &mut region,
                    config.advices[3],
                    0,
                )?;
                region.assign_advice_from_instance(
                    || "anchor",
                    config.instances,
                    ACTION_ANCHOR_INSTANCE_ROW_IDX,
                    config.advices[4],
                    0,
                )?;
                root.copy_advice(|| "root", &mut region, config.advices[5], 0)?;

                let v_normal_input_inv = (spend_note_vars.is_normal.value()
                    * spend_note_vars.value.value())
                .into_field()
                .invert();
                region.assign_advice(
                    || "v_normal_input_inv",
                    config.advices[6],
                    0,
                    || v_normal_input_inv,
                )?;
                let v_normal_output_inv = (output_note_vars.is_normal.value()
                    * output_note_vars.value.value())
                .into_field()
                .invert();
                region.assign_advice(
                    || "v_normal_output_inv",
                    config.advices[7],
                    0,
                    || v_normal_output_inv,
                )?;

                region.assign_advice_from_instance(
                    || "enable input",
                    config.instances,
                    ACTION_ENABLE_INPUT_INSTANCE_ROW_IDX,
                    config.advices[8],
                    0,
                )?;

                region.assign_advice_from_instance(
                    || "enable output",
                    config.instances,
                    ACTION_ENABLE_OUTPUT_INSTANCE_ROW_IDX,
                    config.advices[9],
                    0,
                )?;

                config.basic_checks_selector.enable(&mut region, 0)
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_halo2_action_circuit() {
    use crate::action::ActionInfo;
    use halo2_proofs::{
        dev::MockProver,
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite},
    };
    use pasta_curves::vesta;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let action_info = ActionInfo::dummy(&mut rng);
    let (action, action_circuit) = action_info.build(&mut rng);
    let instances = vec![action.to_instance()];
    {
        let prover = MockProver::<pallas::Base>::run(11, &action_circuit, instances).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // Create action proof
    {
        let params = Params::new(11);
        let empty_circuit: ActionCircuit = Default::default();
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[action_circuit],
            &[&[&action.to_instance()]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::init(&proof[..]);
        assert!(verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&action.to_instance()]],
            &mut transcript
        )
        .is_ok());
    }
}
