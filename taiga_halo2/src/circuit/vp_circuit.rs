use crate::{
    circuit::{
        gadgets::{add::AddChip, assign_free_advice},
        integrity::{check_output_note, check_spend_note, OutputNoteVar, SpendNoteVar},
        note_circuit::{NoteChip, NoteCommitmentChip, NoteConfig},
    },
    constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain, NUM_NOTE,
        SETUP_PARAMS_MAP, VP_CIRCUIT_NULLIFIER_ONE_INSTANCE_IDX,
        VP_CIRCUIT_NULLIFIER_TWO_INSTANCE_IDX, VP_CIRCUIT_OUTPUT_CM_ONE_INSTANCE_IDX,
        VP_CIRCUIT_OUTPUT_CM_TWO_INSTANCE_IDX, VP_CIRCUIT_PARAMS_SIZE,
    },
    note::Note,
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use dyn_clone::{clone_trait_object, DynClone};
use halo2_gadgets::{ecc::chip::EccChip, sinsemilla::chip::SinsemillaChip};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error, VerifyingKey},
};
use pasta_curves::{pallas, vesta};

#[derive(Debug, Clone)]
pub struct VPVerifyingInfo {
    pub vk: VerifyingKey<vesta::Affine>,
    pub proof: Proof,
    pub instance: Vec<pallas::Base>,
}

impl VPVerifyingInfo {
    pub fn verify(&self) -> Result<(), Error> {
        let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        self.proof.verify(&self.vk, params, &[&self.instance])
    }

    pub fn get_nullifiers(&self) -> [pallas::Base; NUM_NOTE] {
        [
            self.instance[VP_CIRCUIT_NULLIFIER_ONE_INSTANCE_IDX],
            self.instance[VP_CIRCUIT_NULLIFIER_TWO_INSTANCE_IDX],
        ]
    }

    pub fn get_note_commitments(&self) -> [pallas::Base; NUM_NOTE] {
        [
            self.instance[VP_CIRCUIT_OUTPUT_CM_ONE_INSTANCE_IDX],
            self.instance[VP_CIRCUIT_OUTPUT_CM_TWO_INSTANCE_IDX],
        ]
    }
}

pub trait ValidityPredicateConfig {
    fn configure_note(meta: &mut ConstraintSystem<pallas::Base>) -> NoteConfig {
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

        NoteChip::configure(meta, instances, advices)
    }
    fn get_note_config(&self) -> NoteConfig;
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self;
}

pub trait ValidityPredicateInfo {
    fn get_spend_notes(&self) -> &[Note; NUM_NOTE];
    fn get_output_notes(&self) -> &[Note; NUM_NOTE];
    fn get_note_instances(&self) -> Vec<pallas::Base> {
        let mut instances = vec![];
        self.get_spend_notes()
            .iter()
            .zip(self.get_output_notes().iter())
            .for_each(|(spend_note, output_note)| {
                let nf = spend_note.get_nf().unwrap().inner();
                instances.push(nf);
                let cm = output_note.commitment();
                instances.push(cm.get_x());
            });

        instances
    }
    fn get_instances(&self) -> Vec<pallas::Base>;
}

pub trait ValidityPredicateVerifyingInfo: DynClone {
    fn get_verifying_info(&self) -> VPVerifyingInfo;
    fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey;
}

clone_trait_object!(ValidityPredicateVerifyingInfo);

pub trait ValidityPredicateCircuit:
    Circuit<pallas::Base> + ValidityPredicateInfo + ValidityPredicateVerifyingInfo
{
    type VPConfig: ValidityPredicateConfig + Clone;
    // Default implementation, constrains the notes integrity.
    // TODO: how to enforce the constraints in vp circuit?
    fn basic_constraints(
        &self,
        config: Self::VPConfig,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(Vec<SpendNoteVar>, Vec<OutputNoteVar>), Error> {
        let note_config = config.get_note_config();
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::<
            NoteCommitmentHashDomain,
            NoteCommitmentDomain,
            NoteCommitmentFixedBases,
        >::load(note_config.sinsemilla_config.clone(), &mut layouter)?;

        // Construct a Sinsemilla chip
        let sinsemilla_chip = SinsemillaChip::construct(note_config.sinsemilla_config.clone());

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(note_config.ecc_config);

        // Construct a NoteCommit chip
        let note_commit_chip =
            NoteCommitmentChip::construct(note_config.note_commit_config.clone());

        // Construct an add chip
        let add_chip = AddChip::<pallas::Base>::construct(note_config.add_config, ());

        let spend_notes = self.get_spend_notes();
        let output_notes = self.get_output_notes();
        let mut spend_note_variables = vec![];
        let mut output_note_variables = vec![];
        for i in 0..NUM_NOTE {
            let spend_note_var = check_spend_note(
                layouter.namespace(|| "check spend note"),
                note_config.advices,
                note_config.instances,
                ecc_chip.clone(),
                sinsemilla_chip.clone(),
                note_commit_chip.clone(),
                note_config.poseidon_config.clone(),
                add_chip.clone(),
                spend_notes[i].clone(),
                i * 2,
            )?;

            // The old_nf may not be from above spend note
            let old_nf = assign_free_advice(
                layouter.namespace(|| "old nf"),
                note_config.advices[0],
                Value::known(output_notes[i].rho.inner()),
            )?;
            let output_note_var = check_output_note(
                layouter.namespace(|| "check output note"),
                note_config.advices,
                note_config.instances,
                ecc_chip.clone(),
                sinsemilla_chip.clone(),
                note_commit_chip.clone(),
                note_config.poseidon_config.clone(),
                output_notes[i].clone(),
                old_nf,
                i * 2 + 1,
            )?;
            spend_note_variables.push(spend_note_var);
            output_note_variables.push(output_note_var);
        }

        Ok((spend_note_variables, output_note_variables))
    }

    // VP designer need to implement the following functions.
    // `get_spend_notes` and `get_output_notes` will be used in `basic_constraints` to get the basic note info.

    // Add custom constraints on basic note variables and user-defined variables.
    fn custom_constraints(
        &self,
        _config: Self::VPConfig,
        mut _layouter: impl Layouter<pallas::Base>,
        _spend_note_variables: &[SpendNoteVar],
        _output_note_variables: &[OutputNoteVar],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[macro_export]
macro_rules! vp_circuit_impl {
    ($name:ident) => {
        impl Circuit<pallas::Base> for $name {
            type Config = <Self as ValidityPredicateCircuit>::VPConfig;
            type FloorPlanner = floor_planner::V1;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
                Self::Config::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                let (spend_note_variables, output_note_variables) = self.basic_constraints(
                    config.clone(),
                    layouter.namespace(|| "basic constraints"),
                )?;
                self.custom_constraints(
                    config,
                    layouter.namespace(|| "custom constraints"),
                    &spend_note_variables,
                    &output_note_variables,
                )?;
                Ok(())
            }
        }

        impl ValidityPredicateVerifyingInfo for $name {
            fn get_verifying_info(&self) -> VPVerifyingInfo {
                let mut rng = OsRng;
                let params = SETUP_PARAMS_MAP.get(&12).unwrap();
                let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
                let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
                let instance = self.get_instances();
                let proof =
                    Proof::create(&pk, params, self.clone(), &[&instance], &mut rng).unwrap();
                VPVerifyingInfo {
                    vk,
                    proof,
                    instance,
                }
            }

            fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey {
                let params = SETUP_PARAMS_MAP.get(&12).unwrap();
                let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
                ValidityPredicateVerifyingKey::from_vk(vk)
            }
        }
    };
}
