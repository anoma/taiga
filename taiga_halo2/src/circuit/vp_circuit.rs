use crate::{
    circuit::{
        gadgets::{
            add::{AddChip, AddConfig},
            assign_free_advice,
            conditional_equal::ConditionalEqualConfig,
            extended_or_relation::ExtendedOrRelationConfig,
            mul::{MulChip, MulConfig},
            sub::{SubChip, SubConfig},
            target_note_variable::{GetIsInputNoteFlagConfig, GetOwnedNoteVariableConfig},
        },
        integrity::{check_input_note, check_output_note},
        note_circuit::{NoteChip, NoteCommitmentChip, NoteConfig},
    },
    constant::{
        NoteCommitmentDomain, NoteCommitmentHashDomain, TaigaFixedBases, NUM_NOTE,
        SETUP_PARAMS_MAP, VP_CIRCUIT_NULLIFIER_ONE_INSTANCE_IDX,
        VP_CIRCUIT_NULLIFIER_TWO_INSTANCE_IDX, VP_CIRCUIT_OUTPUT_CM_ONE_INSTANCE_IDX,
        VP_CIRCUIT_OUTPUT_CM_TWO_INSTANCE_IDX, VP_CIRCUIT_OWNED_NOTE_PUB_ID_INSTANCE_IDX,
        VP_CIRCUIT_PARAMS_SIZE,
    },
    note::Note,
    proof::Proof,
    vp_vk::ValidityPredicateVerifyingKey,
};
use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{ReadBytesExt, WriteBytesExt};
use dyn_clone::{clone_trait_object, DynClone};
use ff::PrimeField;
use halo2_gadgets::{ecc::chip::EccChip, sinsemilla::chip::SinsemillaChip};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{
        keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance,
        VerifyingKey,
    },
    poly::commitment::Params,
};
use pasta_curves::{pallas, vesta, EqAffine, Fp};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use vamp_ir::ast::{Module, Pat, VariableId};
use vamp_ir::halo2::synth::{make_constant, Halo2Module, PrimeFieldOps};
use vamp_ir::transform::{collect_module_variables, compile};
use vamp_ir::util::{read_inputs_from_file, Config};

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

impl BorshSerialize for VPVerifyingInfo {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        // Write vk
        self.vk.write(writer)?;
        // Write proof
        self.proof.serialize(writer)?;
        // Write instance
        assert!(self.instance.len() < 256);
        writer.write_u8(self.instance.len() as u8)?;
        for ele in self.instance.iter() {
            writer.write_all(&ele.to_repr())?;
        }
        Ok(())
    }
}

impl BorshDeserialize for VPVerifyingInfo {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        // TODO: Read vk
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        let vk = VerifyingKey::read::<_, TrivialValidityPredicateCircuit>(buf, params)?;
        // Read proof
        let proof = Proof::deserialize(buf)?;
        // Read instance
        let instance_len = buf.read_u8()?;
        let instance: Vec<_> = (0..instance_len)
            .map(|_| {
                let bytes = <[u8; 32]>::deserialize(buf)?;
                Option::from(pallas::Base::from_repr(bytes)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "instance not in field")
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(VPVerifyingInfo {
            vk,
            proof,
            instance,
        })
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

#[derive(Clone, Debug)]
pub struct GeneralVerificationValidityPredicateConfig {
    pub note_conifg: NoteConfig,
    pub advices: [Column<Advice>; 10],
    pub instances: Column<Instance>,
    pub get_is_input_note_flag_config: GetIsInputNoteFlagConfig,
    pub get_owned_note_variable_config: GetOwnedNoteVariableConfig,
    pub conditional_equal_config: ConditionalEqualConfig,
    pub extended_or_relation_config: ExtendedOrRelationConfig,
    pub add_config: AddConfig,
    pub sub_config: SubConfig,
    pub mul_config: MulConfig,
}

impl ValidityPredicateConfig for GeneralVerificationValidityPredicateConfig {
    fn get_note_config(&self) -> NoteConfig {
        self.note_conifg.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let note_conifg = Self::configure_note(meta);

        let advices = note_conifg.advices;
        let instances = note_conifg.instances;

        let get_owned_note_variable_config = GetOwnedNoteVariableConfig::configure(
            meta,
            advices[0],
            [advices[1], advices[2], advices[3], advices[4]],
        );

        let get_is_input_note_flag_config =
            GetIsInputNoteFlagConfig::configure(meta, advices[0], advices[1], advices[2]);

        let conditional_equal_config =
            ConditionalEqualConfig::configure(meta, [advices[0], advices[1], advices[2]]);

        let add_config = note_conifg.add_config.clone();
        let sub_config = SubChip::configure(meta, [advices[0], advices[1]]);
        let mul_config = MulChip::configure(meta, [advices[0], advices[1]]);

        let extended_or_relation_config =
            ExtendedOrRelationConfig::configure(meta, [advices[0], advices[1], advices[2]]);

        Self {
            note_conifg,
            advices,
            instances,
            get_is_input_note_flag_config,
            get_owned_note_variable_config,
            conditional_equal_config,
            extended_or_relation_config,
            add_config,
            sub_config,
            mul_config,
        }
    }
}

pub trait ValidityPredicateInfo {
    fn get_input_notes(&self) -> &[Note; NUM_NOTE];
    fn get_output_notes(&self) -> &[Note; NUM_NOTE];
    fn get_note_instances(&self) -> Vec<pallas::Base> {
        let mut instances = vec![];
        self.get_input_notes()
            .iter()
            .zip(self.get_output_notes().iter())
            .for_each(|(input_note, output_note)| {
                let nf = input_note.get_nf().unwrap().inner();
                instances.push(nf);
                let cm = output_note.commitment();
                instances.push(cm.get_x());
            });
        instances.push(self.get_owned_note_pub_id());
        instances
    }
    fn get_instances(&self) -> Vec<pallas::Base>;
    // The owned_note_pub_id is the input_note_nf or the output_note_cm_x
    // The owned_note_pub_id is the key to look up the target variables and
    // help determine whether the owned note is the input note or not in VP circuit.
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
        SinsemillaChip::<NoteCommitmentHashDomain, NoteCommitmentDomain, TaigaFixedBases>::load(
            note_config.sinsemilla_config.clone(),
            &mut layouter,
        )?;

        // Construct a Sinsemilla chip
        let sinsemilla_chip = SinsemillaChip::construct(note_config.sinsemilla_config.clone());

        // Construct an ECC chip
        let ecc_chip = EccChip::construct(note_config.ecc_config);

        // Construct a NoteCommit chip
        let note_commit_chip =
            NoteCommitmentChip::construct(note_config.note_commit_config.clone());

        // Construct an add chip
        let add_chip = AddChip::<pallas::Base>::construct(note_config.add_config, ());

        let input_notes = self.get_input_notes();
        let output_notes = self.get_output_notes();
        let mut input_note_variables = vec![];
        let mut output_note_variables = vec![];
        for i in 0..NUM_NOTE {
            input_note_variables.push(check_input_note(
                layouter.namespace(|| "check input note"),
                note_config.advices,
                note_config.instances,
                ecc_chip.clone(),
                sinsemilla_chip.clone(),
                note_commit_chip.clone(),
                note_config.poseidon_config.clone(),
                add_chip.clone(),
                input_notes[i],
                i * 2,
            )?);

            // The old_nf may not be from above input note
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
                output_notes[i],
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
            input_note_variables: input_note_variables.try_into().unwrap(),
            output_note_variables: output_note_variables.try_into().unwrap(),
        })
    }

    // VP designer need to implement the following functions.
    // `get_input_notes` and `get_output_notes` will be used in `basic_constraints` to get the basic note info.

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
    pub input_note_variables: [InputNoteVariables; NUM_NOTE],
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
    pub rho: AssignedCell<pallas::Base, pallas::Base>,
    pub nk_com: AssignedCell<pallas::Base, pallas::Base>,
    pub psi: AssignedCell<pallas::Base, pallas::Base>,
    pub rcm: AssignedCell<pallas::Base, pallas::Base>,
}

// Variables in the input note
#[derive(Debug, Clone)]
pub struct InputNoteVariables {
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
    // src_variable is the input_note_nf or the output_note_cm_x
    pub src_variable: AssignedCell<pallas::Base, pallas::Base>,
    // target_variable is one of the parameter in the NoteVariables
    pub target_variable: AssignedCell<pallas::Base, pallas::Base>,
}

impl BasicValidityPredicateVariables {
    pub fn get_owned_note_pub_id(&self) -> AssignedCell<pallas::Base, pallas::Base> {
        self.owned_note_pub_id.clone()
    }

    pub fn get_input_note_nfs(&self) -> [AssignedCell<pallas::Base, pallas::Base>; NUM_NOTE] {
        let ret: Vec<_> = self
            .input_note_variables
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
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
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
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_app_vk_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
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
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_app_data_static_searchable_pairs(
        &self,
    ) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
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
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_value_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
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
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_is_merkle_checked_searchable_pairs(
        &self,
    ) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
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
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_app_data_dynamic_searchable_pairs(
        &self,
    ) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
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
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_rho_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.rho.clone(),
            })
            .collect();

        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.rho.clone(),
            })
            .collect();
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_nk_com_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.nk_com.clone(),
            })
            .collect();

        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.nk_com.clone(),
            })
            .collect();
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_psi_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.psi.clone(),
            })
            .collect();

        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.psi.clone(),
            })
            .collect();
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
    }

    pub fn get_rcm_searchable_pairs(&self) -> [NoteSearchableVariablePair; NUM_NOTE * 2] {
        let mut input_note_pairs: Vec<_> = self
            .input_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: variables.note_variables.rcm.clone(),
            })
            .collect();

        let output_note_pairs: Vec<_> = self
            .output_note_variables
            .iter()
            .map(|variables| NoteSearchableVariablePair {
                src_variable: variables.cm_x.clone(),
                target_variable: variables.note_variables.rcm.clone(),
            })
            .collect();
        input_note_pairs.extend(output_note_pairs);
        input_note_pairs.try_into().unwrap()
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

/// Convert named circuit assignments to assignments of vamp-ir variableIds.
/// Useful for calling vamp-ir Halo2Module::populate_variable_assigments
pub fn get_circuit_assignments(
    module: &Module,
    named_assignments: &HashMap<String, Fp>,
) -> HashMap<VariableId, Fp> {
    let mut input_variables = HashMap::new();
    collect_module_variables(module, &mut input_variables);
    // Defined variables should not be requested from user
    for def in &module.defs {
        if let Pat::Variable(var) = &def.0 .0.v {
            input_variables.remove(&var.id);
        }
    }

    let variable_assignments = input_variables
        .iter()
        .map(|(id, expected_var)| {
            let var_name = expected_var.name.as_deref().unwrap_or_else(|| {
                panic!(
                    "could not find circuit variable with expected id {}",
                    expected_var.id
                )
            });
            let assignment = *named_assignments.get(var_name).unwrap_or_else(|| {
                panic!("missing assignment for variable with name {}", var_name)
            });
            (*id, assignment)
        })
        .collect();
    variable_assignments
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
    pub fn from_vamp_ir_source(
        vamp_ir_source: &str,
        named_field_assignments: HashMap<String, Fp>,
    ) -> Self {
        let config = Config { quiet: true };
        let parsed_vamp_ir_module = Module::parse(vamp_ir_source).unwrap();
        let vamp_ir_module = compile(
            parsed_vamp_ir_module,
            &PrimeFieldOps::<Fp>::default(),
            &config,
        );
        let mut circuit = Halo2Module::<Fp>::new(Rc::new(vamp_ir_module));
        let params = Params::new(circuit.k);
        let field_assignments = get_circuit_assignments(&circuit.module, &named_field_assignments);

        // Populate variable definitions
        circuit.populate_variables(field_assignments.clone());

        // Get public inputs Fp
        let instances = circuit
            .module
            .pubs
            .iter()
            .map(|inst| field_assignments[&inst.id])
            .collect::<Vec<pallas::Base>>();

        Self {
            params,
            circuit,
            instances,
        }
    }

    pub fn from_vamp_ir_file(vamp_ir_file: &PathBuf, inputs_file: &PathBuf) -> Self {
        let config = Config { quiet: true };
        let vamp_ir_source = fs::read_to_string(vamp_ir_file).expect("cannot read vamp-ir file");
        let parsed_vamp_ir_module = Module::parse(&vamp_ir_source).unwrap();
        let vamp_ir_module = compile(
            parsed_vamp_ir_module,
            &PrimeFieldOps::<Fp>::default(),
            &config,
        );
        let mut circuit = Halo2Module::<Fp>::new(Rc::new(vamp_ir_module));
        let params: Params<EqAffine> = Params::new(circuit.k);

        let var_assignments_ints = read_inputs_from_file(&circuit.module, inputs_file);
        let mut var_assignments = HashMap::new();
        for (k, v) in var_assignments_ints {
            var_assignments.insert(k, make_constant(v));
        }

        // Populate variable definitions
        circuit.populate_variables(var_assignments.clone());

        // Get public inputs Fp
        let instances = circuit
            .module
            .pubs
            .iter()
            .map(|inst| var_assignments[&inst.id])
            .collect::<Vec<pallas::Base>>();

        Self {
            params,
            circuit,
            instances,
        }
    }
}

impl ValidityPredicateVerifyingInfo for VampIRValidityPredicateCircuit {
    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        let pk =
            keygen_pk(&self.params, vk.clone(), &self.circuit).expect("keygen_pk should not fail");
        let proof = Proof::create(
            &pk,
            &self.params,
            self.circuit.clone(),
            &[&self.instances],
            &mut rng,
        )
        .unwrap();
        VPVerifyingInfo {
            vk,
            proof,
            instance: self.instances.clone(),
        }
    }

    fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey {
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
    }
}

#[test]
fn test_create_vp_from_vamp_ir_file() {
    let vamp_ir_circuit_file = PathBuf::from("./src/circuit/vamp_ir_circuits/pyth.pir");
    let inputs_file = PathBuf::from("./src/circuit/vamp_ir_circuits/pyth.inputs");
    let vp_circuit =
        VampIRValidityPredicateCircuit::from_vamp_ir_file(&vamp_ir_circuit_file, &inputs_file);

    // generate proof and instance
    let vp_info = vp_circuit.get_verifying_info();

    // verify the proof
    // TODO: use the vp_info.verify() instead. vp_info.verify() doesn't work now because it uses the fixed VP_CIRCUIT_PARAMS_SIZE params.
    vp_info
        .proof
        .verify(&vp_info.vk, &vp_circuit.params, &[&vp_info.instance])
        .unwrap();
}
