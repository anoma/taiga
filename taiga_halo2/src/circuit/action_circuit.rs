use crate::circuit::gadgets::AddChip;
use crate::circuit::integrity::{check_output_note, check_spend_note};
use crate::circuit::merkle_circuit::{
    merkle_poseidon_gadget, MerklePoseidonChip, MerklePoseidonConfig,
};
use crate::circuit::note_circuit::{NoteChip, NoteCommitmentChip, NoteConfig};
use crate::constant::{
    NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain,
    ACTION_NF_INSTANCE_ROW_IDX, ACTION_OUTPUT_CM_INSTANCE_ROW_IDX, ACTION_ROOT_INSTANCE_ROW_IDX,
    TAIGA_COMMITMENT_TREE_DEPTH,
};
use crate::note::Note;
use halo2_gadgets::{ecc::chip::EccChip, sinsemilla::chip::SinsemillaChip};
use halo2_proofs::{
    circuit::{floor_planner, Layouter},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::pallas;

use super::circuit_parameters::CircuitParameters;

#[derive(Clone, Debug)]
pub struct ActionConfig {
    instances: Column<Instance>,
    advices: [Column<Advice>; 10],
    note_config: NoteConfig,
    merkle_config: MerklePoseidonConfig,
}

/// The Action circuit.
#[derive(Clone, Debug, Default)]
pub struct ActionCircuit<CP: CircuitParameters> {
    /// Spent note
    pub spend_note: Note<CP>,
    /// The authorization path of spend note
    pub auth_path: [(CP::CurveScalarField, bool); TAIGA_COMMITMENT_TREE_DEPTH],
    /// Output note
    pub output_note: Note<CP>,
}

impl<CP: CircuitParameters> Circuit<CP::CurveScalarField> for ActionCircuit<CP> {
    type Config = ActionConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<CP::CurveScalarField>) -> Self::Config {
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
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<CP::CurveScalarField>,
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
        let add_chip = AddChip::<CP::CurveScalarField>::construct(config.note_config.add_config, ());

        // Construct a merkle chip
        let merkle_chip = MerklePoseidonChip::construct(config.merkle_config);

        // Spend note
        let nf = {
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

            // Public root
            layouter.constrain_instance(
                root.cell(),
                config.instances,
                ACTION_ROOT_INSTANCE_ROW_IDX,
            )?;

            // TODO: user send address VP commitment and token VP commitment

            spend_note_vars.nf
        };

        // Output note
        {
            let _output_note_vars = check_output_note(
                layouter.namespace(|| "check output note"),
                config.advices,
                config.instances,
                ecc_chip,
                sinsemilla_chip,
                note_commit_chip,
                config.note_config.poseidon_config,
                self.output_note.clone(),
                nf,
                ACTION_OUTPUT_CM_INSTANCE_ROW_IDX,
            )?;

            // TODO: add user receive address VP commitment and token VP commitment

            // TODO: add note verifiable encryption
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
        let prover = MockProver::<CP::CurveScalarField>::run(11, &action_circuit, instances).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // Create action proof
    {
        let params = Params::new(11);
        let empty_circuit: ActionCircuit = Default::default();
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        let mut transcript = Blake2bWrite::<_, CP::Curve, _>::init(vec![]);
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
