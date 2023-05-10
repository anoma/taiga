use crate::{
    circuit::{
        gadgets::{add::AddChip, assign_free_advice},
        integrity::{check_output_note, check_spend_note},
        note_circuit::{NoteChip, NoteCommitmentChip, NoteConfig},
    },
    constant::{
        NoteCommitmentDomain, NoteCommitmentFixedBases, NoteCommitmentHashDomain, NUM_NOTE,
        SETUP_PARAMS_MAP, VP_CIRCUIT_NULLIFIER_ONE_INSTANCE_IDX,
        VP_CIRCUIT_NULLIFIER_TWO_INSTANCE_IDX, VP_CIRCUIT_OUTPUT_CM_ONE_INSTANCE_IDX,
        VP_CIRCUIT_OUTPUT_CM_TWO_INSTANCE_IDX, VP_CIRCUIT_OWNED_NOTE_PUB_ID_INSTANCE_IDX,
        VP_CIRCUIT_PARAMS_SIZE,
    },
    note::Note,
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use bincode::error::DecodeError;
use dyn_clone::{clone_trait_object, DynClone};
use halo2_gadgets::{ecc::chip::EccChip, sinsemilla::chip::SinsemillaChip};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error, VerifyingKey},
    poly::commitment::Params,
};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use vamp_ir::halo2::synth::{make_constant, Halo2Module};
use vamp_ir::util::read_inputs_from_file;

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

    pub fn get_owned_note_pub_id(&self) -> pallas::Base {
        self.instance[VP_CIRCUIT_OWNED_NOTE_PUB_ID_INSTANCE_IDX]
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
        instances.push(self.get_owned_note_pub_id());
        instances
    }
    fn get_instances(&self) -> Vec<pallas::Base>;
    // The owned_note_pub_id is the spend_note_nf or the output_note_cm_x
    // The owned_note_pub_id is the key to look up the target variables and
    // help determine whether the owned note is the spend note or not in VP circuit.
    fn get_owned_note_pub_id(&self) -> pallas::Base;
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
    ) -> Result<BasicValidityPredicateVariables, Error> {
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
            spend_note_variables.push(check_spend_note(
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
            )?);

            // The old_nf may not be from above spend note
            let old_nf = assign_free_advice(
                layouter.namespace(|| "old nf"),
                note_config.advices[0],
                Value::known(output_notes[i].rho.inner()),
            )?;
            output_note_variables.push(check_output_note(
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
            )?);
        }

        // Publicize the owned_note_pub_id
        let owned_note_pub_id = assign_free_advice(
            layouter.namespace(|| "owned_note_pub_id"),
            note_config.advices[0],
            Value::known(self.get_owned_note_pub_id()),
        )?;
        layouter.constrain_instance(
            owned_note_pub_id.cell(),
            note_config.instances,
            VP_CIRCUIT_OWNED_NOTE_PUB_ID_INSTANCE_IDX,
        )?;

        Ok(BasicValidityPredicateVariables {
            owned_note_pub_id,
            spend_note_variables: spend_note_variables.try_into().unwrap(),
            output_note_variables: output_note_variables.try_into().unwrap(),
        })
    }

    // VP designer need to implement the following functions.
    // `get_spend_notes` and `get_output_notes` will be used in `basic_constraints` to get the basic note info.

    // Add custom constraints on basic note variables and user-defined variables.
    fn custom_constraints(
        &self,
        _config: Self::VPConfig,
        mut _layouter: impl Layouter<pallas::Base>,
        _basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// BasicValidityPredicateVariables are generally constrained in ValidityPredicateCircuit::basic_constraints
/// and will be used in ValidityPredicateCircuit::custom_constraints
#[derive(Debug, Clone)]
pub struct BasicValidityPredicateVariables {
    pub owned_note_pub_id: AssignedCell<pallas::Base, pallas::Base>,
    pub spend_note_variables: [SpendNoteVariables; NUM_NOTE],
    pub output_note_variables: [OutputNoteVariables; NUM_NOTE],
}

#[derive(Debug, Clone)]
pub struct NoteVariables {
    pub address: AssignedCell<pallas::Base, pallas::Base>,
    pub app_vk: AssignedCell<pallas::Base, pallas::Base>,
    pub app_data_static: AssignedCell<pallas::Base, pallas::Base>,
    pub value: AssignedCell<pallas::Base, pallas::Base>,
    pub is_merkle_checked: AssignedCell<pallas::Base, pallas::Base>,
    pub app_data_dynamic: AssignedCell<pallas::Base, pallas::Base>,
}

// Variables in the spend note
#[derive(Debug, Clone)]
pub struct SpendNoteVariables {
    pub nf: AssignedCell<pallas::Base, pallas::Base>,
    pub cm_x: AssignedCell<pallas::Base, pallas::Base>,
    pub note_variables: NoteVariables,
}

// Variables in the out note
#[derive(Debug, Clone)]
pub struct OutputNoteVariables {
    pub cm_x: AssignedCell<pallas::Base, pallas::Base>,
    pub note_variables: NoteVariables,
}

#[derive(Debug, Clone)]
pub struct NoteSearchableVariablePair {
    // src_variable is the spend_note_nf or the output_note_cm_x
    pub src_variable: AssignedCell<pallas::Base, pallas::Base>,
    // target_variable is one of the parameter in the NoteVariables
    pub target_variable: AssignedCell<pallas::Base, pallas::Base>,
}

impl BasicValidityPredicateVariables {
    pub fn get_owned_note_pub_id(&self) -> AssignedCell<pallas::Base, pallas::Base> {
        self.owned_note_pub_id.clone()
    }

    pub fn get_spend_note_nfs(&self) -> [AssignedCell<pallas::Base, pallas::Base>; NUM_NOTE] {
        let ret: Vec<_> = self
            .spend_note_variables
            .iter()
            .map(|variables| variables.nf.clone())
            .collect();
        ret.try_into().unwrap()
    }

    pub fn get_output_note_cms(&self) -> [AssignedCell<pallas::Base, pallas::Base>; NUM_NOTE] {
        let ret: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| variables.cm_x.clone())
            .collect();
        ret.try_into().unwrap()
    }

    pub fn get_address_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut spend_note_pairs: Vec<_> = self
            .spend_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.address.clone(),
            })
            .collect();
        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.address.clone(),
            })
            .collect();
        spend_note_pairs.extend(output_note_pairs);
        spend_note_pairs.try_into().unwrap()
    }

    pub fn get_app_vk_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut spend_note_pairs: Vec<_> = self
            .spend_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.app_vk.clone(),
            })
            .collect();
        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.app_vk.clone(),
            })
            .collect();
        spend_note_pairs.extend(output_note_pairs);
        spend_note_pairs.try_into().unwrap()
    }

    pub fn get_app_data_static_searchable_pairs(
        &self,
    ) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut spend_note_pairs: Vec<_> = self
            .spend_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.app_data_static.clone(),
            })
            .collect();
        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.app_data_static.clone(),
            })
            .collect();
        spend_note_pairs.extend(output_note_pairs);
        spend_note_pairs.try_into().unwrap()
    }

    pub fn get_value_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut spend_note_pairs: Vec<_> = self
            .spend_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.value.clone(),
            })
            .collect();
        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.value.clone(),
            })
            .collect();
        spend_note_pairs.extend(output_note_pairs);
        spend_note_pairs.try_into().unwrap()
    }

    pub fn get_is_merkle_checked_searchable_pairs(
        &self,
    ) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut spend_note_pairs: Vec<_> = self
            .spend_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.is_merkle_checked.clone(),
            })
            .collect();
        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.is_merkle_checked.clone(),
            })
            .collect();
        spend_note_pairs.extend(output_note_pairs);
        spend_note_pairs.try_into().unwrap()
    }

    pub fn get_app_data_dynamic_searchable_pairs(
        &self,
    ) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut spend_note_pairs: Vec<_> = self
            .spend_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.app_data_dynamic.clone(),
            })
            .collect();
        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.app_data_dynamic.clone(),
            })
            .collect();
        spend_note_pairs.extend(output_note_pairs);
        spend_note_pairs.try_into().unwrap()
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
                let basic_variables = self.basic_constraints(
                    config.clone(),
                    layouter.namespace(|| "basic constraints"),
                )?;
                self.custom_constraints(
                    config,
                    layouter.namespace(|| "custom constraints"),
                    basic_variables,
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

#[derive(Clone)]
pub struct VampIRValidityPredicateCircuit {
    // TODO: vamp_ir doesn't support to set the params size manually, add the params here temporarily.
    // remove the params once we can set it as VP_CIRCUIT_PARAMS_SIZE in vamp_ir.
    pub params: Params<vesta::Affine>,
    pub circuit: Halo2Module<pallas::Base>,
    pub instances: Vec<pallas::Base>,
}

impl VampIRValidityPredicateCircuit {
    pub fn from_vamp_ir_circuit(vamp_ir_circuit_file: &PathBuf, inputs_file: &PathBuf) -> Self {
        let mut circuit_file =
            File::open(vamp_ir_circuit_file).expect("unable to load circuit file");
        // let mut circuit: Halo2Module<pallas::Base> =
        //     bincode::decode_from_std_read(&mut circuit_file, bincode::config::standard())
        //         .expect("unable to load circuit file");
        let HaloCircuitData {
            params,
            mut circuit,
        } = HaloCircuitData::read(&mut circuit_file).unwrap();
        let var_assignments_ints = read_inputs_from_file(&circuit.module, inputs_file);
        let mut var_assignments = HashMap::new();
        for (k, v) in var_assignments_ints {
            var_assignments.insert(k, make_constant(v));
        }

        // Populate variable definitions
        circuit.populate_variables(var_assignments);

        // TODO: export and handle the instances
        Self {
            params,
            circuit,
            instances: vec![],
        }
    }
}

impl ValidityPredicateVerifyingInfo for VampIRValidityPredicateCircuit {
    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        // let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        let pk =
            keygen_pk(&self.params, vk.clone(), &self.circuit).expect("keygen_pk should not fail");
        // TODO: export and handle the instances
        let proof = Proof::create(&pk, &self.params, self.circuit.clone(), &[], &mut rng).unwrap();
        VPVerifyingInfo {
            vk,
            proof,
            instance: self.instances.clone(),
        }
    }

    fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey {
        // let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
    }
}

// TODO: We won't need the HaloCircuitData when we can import the circuit from vamp_ir.
struct HaloCircuitData {
    params: Params<vesta::Affine>,
    circuit: Halo2Module<pallas::Base>,
}

impl HaloCircuitData {
    fn read<R>(mut reader: R) -> Result<Self, DecodeError>
    where
        R: std::io::Read,
    {
        let params = Params::<vesta::Affine>::read(&mut reader)
            .map_err(|x| DecodeError::OtherString(x.to_string()))?;
        let circuit: Halo2Module<pallas::Base> =
            bincode::decode_from_std_read(&mut reader, bincode::config::standard())?;
        Ok(Self { params, circuit })
    }
}

#[test]
fn test_create_vp_from_vamp_ir_circuit() {
    let vamp_ir_circuit_file = PathBuf::from("./src/circuit/vamp_ir_circuits/pyth.halo2");
    let inputs_file = PathBuf::from("./src/circuit/vamp_ir_circuits/pyth.inputs");
    let vp_circuit =
        VampIRValidityPredicateCircuit::from_vamp_ir_circuit(&vamp_ir_circuit_file, &inputs_file);

    // generate proof and instance
    let vp_info = vp_circuit.get_verifying_info();

    // verify the proof
    // TODO: use the vp_info.verify() instead. vp_info.verify() doesn't work now because it uses the fixed VP_CIRCUIT_PARAMS_SIZE params.
    // TODO: export and handle the instances
    vp_info
        .proof
        .verify(&vp_info.vk, &vp_circuit.params, &[])
        .unwrap();
}
