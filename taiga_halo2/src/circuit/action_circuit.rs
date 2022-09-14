use crate::circuit::gadgets::{AddChip, AddConfig};
use crate::circuit::integrity::{check_output_note, check_spend_note};
use crate::circuit::merkle_circuit::{
    merkle_poseidon_gadget, MerklePoseidonChip, MerklePoseidonConfig,
};
use crate::circuit::note_commitment::{
    NoteCommitmentChip, NoteCommitmentConfig, NoteCommitmentDomain, NoteCommitmentFixedBases,
    NoteCommitmentHashDomain,
};
use crate::constant::TAIGA_COMMITMENT_TREE_DEPTH;
use crate::note::Note;
use halo2_gadgets::{
    ecc::chip::{EccChip, EccConfig},
    poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig},
    sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
    utilities::lookup_range_check::LookupRangeCheckConfig,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;

#[derive(Clone, Debug)]
pub struct ActionConfig {
    instances: Column<Instance>,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    ecc_config: EccConfig<NoteCommitmentFixedBases>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    sinsemilla_config:
        SinsemillaConfig<NoteCommitmentHashDomain, NoteCommitmentDomain, NoteCommitmentFixedBases>,
    note_commit_config: NoteCommitmentConfig,
    merkle_config: MerklePoseidonConfig,
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

        let add_config = AddChip::configure(meta, advices[0..2].try_into().unwrap());

        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

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

        let ecc_config = EccChip::<NoteCommitmentFixedBases>::configure(
            meta,
            advices,
            lagrange_coeffs,
            range_check,
        );

        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            lagrange_coeffs[2..5].try_into().unwrap(),
            lagrange_coeffs[5..8].try_into().unwrap(),
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

        let note_commit_config =
            NoteCommitmentChip::configure(meta, advices, sinsemilla_config.clone());

        let merkle_config = MerklePoseidonChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            poseidon_config.clone(),
        );

        Self::Config {
            instances,
            advices,
            add_config,
            ecc_config,
            poseidon_config,
            sinsemilla_config,
            note_commit_config,
            merkle_config,
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
        >::load(config.note_commit_config.sinsemilla_config.clone(), &mut layouter)?;

        // Construct a Sinsemilla chip
        let sinsemilla_chip = SinsemillaChip::construct(config.sinsemilla_config.clone());

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(config.ecc_config);

        // Construct a NoteCommit chip
        let note_commit_chip = NoteCommitmentChip::construct(config.note_commit_config.clone());

        // Construct an add chip
        let add_chip = AddChip::<pallas::Base>::construct(config.add_config, ());

        // Construct a merkle chip
        let merkle_chip = MerklePoseidonChip::construct(config.merkle_config);

        // Spend note
        let nf = {
            // Check the spend note commitment
            let spend_note_vars = check_spend_note(
                layouter.namespace(|| "check spend note"),
                config.advices,
                ecc_chip.clone(),
                sinsemilla_chip.clone(),
                note_commit_chip.clone(),
                config.poseidon_config.clone(),
                add_chip,
                self.spend_note.clone(),
            )?;

            // Public nullifier
            layouter.constrain_instance(spend_note_vars.nf.cell(), config.instances, 0)?;

            // Check the merkle tree path validity and public the root
            let leaf = spend_note_vars.cm.extract_p().inner().clone();
            let root = merkle_poseidon_gadget(
                layouter.namespace(|| "poseidon merkle"),
                merkle_chip,
                leaf,
                &self.auth_path,
            )?;

            // Public root
            layouter.constrain_instance(root.cell(), config.instances, 1)?;

            // TODO: user send address VP commitment and token VP commitment

            spend_note_vars.nf
        };

        // Output note
        {
            let output_note_vars = check_output_note(
                layouter.namespace(|| "check output note"),
                config.advices,
                ecc_chip,
                sinsemilla_chip,
                note_commit_chip,
                config.poseidon_config,
                self.output_note.clone(),
                nf,
            )?;

            // TODO: add user receive address VP commitment and token VP commitment

            // TODO: add note verifiable encryption

            // Public cm
            let cm = output_note_vars.cm.extract_p().inner().clone();
            layouter.constrain_instance(cm.cell(), config.instances, 2)?;
        }

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
        let prover =
            MockProver::<pallas::Base>::run(11, &action_circuit, instances).unwrap();
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
