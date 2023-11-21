use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        blake2s::Blake2sConfig,
        gadgets::{
            add::{AddChip, AddConfig},
            assign_free_advice,
            conditional_equal::ConditionalEqualConfig,
            conditional_select::ConditionalSelectConfig,
            extended_or_relation::ExtendedOrRelationConfig,
            mul::{MulChip, MulConfig},
            sub::{SubChip, SubConfig},
            target_resource_variable::{
                GetIsInputResourceFlagConfig, GetOwnedResourceVariableConfig,
            },
        },
        integrity::{check_input_resource, check_output_resource},
        resource_commitment::{ResourceCommitChip, ResourceCommitConfig},
        vamp_ir_utils::{get_circuit_assignments, parse, VariableAssignmentError},
    },
    constant::{
        TaigaFixedBases, NOTE_ENCRYPTION_CIPHERTEXT_NUM, NUM_RESOURCE, SETUP_PARAMS_MAP,
        VP_CIRCUIT_NOTE_ENCRYPTION_PK_X_IDX, VP_CIRCUIT_NOTE_ENCRYPTION_PK_Y_IDX,
        VP_CIRCUIT_NOTE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX,
        VP_CIRCUIT_NULLIFIER_ONE_PUBLIC_INPUT_IDX, VP_CIRCUIT_NULLIFIER_TWO_PUBLIC_INPUT_IDX,
        VP_CIRCUIT_OUTPUT_CM_ONE_PUBLIC_INPUT_IDX, VP_CIRCUIT_OUTPUT_CM_TWO_PUBLIC_INPUT_IDX,
        VP_CIRCUIT_OWNED_RESOURCE_ID_PUBLIC_INPUT_IDX, VP_CIRCUIT_PARAMS_SIZE,
        VP_CIRCUIT_PUBLIC_INPUT_NUM,
    },
    error::TransactionError,
    note_encryption::{NoteCiphertext, SecretKey},
    proof::Proof,
    resource::{RandomSeed, Resource, ResourceCommitment},
    utils::mod_r_p,
    vp_vk::ValidityPredicateVerifyingKey,
};
use dyn_clone::{clone_trait_object, DynClone};
use group::cofactor::CofactorCurveAffine;
use halo2_gadgets::{
    ecc::chip::EccChip,
    ecc::chip::EccConfig,
    poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig},
    utilities::lookup_range_check::LookupRangeCheckConfig,
};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{
        keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error, Instance,
        TableColumn, VerifyingKey,
    },
    poly::commitment::Params,
};
use pasta_curves::{pallas, vesta, EqAffine, Fp};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::fs;
//use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use vamp_ir::ast::Module;
use vamp_ir::halo2::synth::{make_constant, Halo2Module, PrimeFieldOps};
use vamp_ir::transform::compile;
use vamp_ir::util::{read_inputs_from_file, Config};

#[cfg(feature = "serde")]
use serde;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(feature = "nif")]
use rustler::types::atom;
#[cfg(feature = "nif")]
use rustler::{Decoder, Encoder, Env, NifResult, Term};

pub type ValidityPredicate = dyn ValidityPredicateVerifyingInfo;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VPVerifyingInfo {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serde_serialize_verifying_key",
            deserialize_with = "serde_deserialize_verifying_key"
        )
    )]
    pub vk: VerifyingKey<vesta::Affine>,
    pub proof: Proof,
    pub public_inputs: ValidityPredicatePublicInputs,
}

#[cfg(feature = "nif")]
rustler::atoms! {verifying_info}

#[cfg(feature = "nif")]
impl Encoder for VPVerifyingInfo {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        (
            verifying_info().encode(env),
            self.vk.to_bytes().encode(env),
            self.proof.encode(env),
            self.public_inputs.encode(env),
        )
            .encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for VPVerifyingInfo {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let (term, vk, proof, public_inputs): (
            atom::Atom,
            Vec<u8>,
            Proof,
            ValidityPredicatePublicInputs,
        ) = term.decode()?;
        if term == verifying_info() {
            use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
            let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
            let vk = VerifyingKey::from_bytes::<TrivialValidityPredicateCircuit>(&vk, params)
                .map_err(|_e| rustler::Error::Atom("failure to decode"))?;
            Ok(VPVerifyingInfo {
                vk,
                proof,
                public_inputs,
            })
        } else {
            Err(rustler::Error::BadArg)
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidityPredicatePublicInputs([pallas::Base; VP_CIRCUIT_PUBLIC_INPUT_NUM]);

#[cfg(feature = "nif")]
impl Encoder for ValidityPredicatePublicInputs {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.0.to_vec().encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for ValidityPredicatePublicInputs {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let val: Vec<pallas::Base> = Decoder::decode(term)?;
        val.try_into()
            .map_err(|_e| rustler::Error::Atom("failure to decode"))
    }
}

impl VPVerifyingInfo {
    pub fn verify(&self) -> Result<(), Error> {
        let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        self.proof
            .verify(&self.vk, params, &[self.public_inputs.inner()])
    }

    pub fn get_nullifiers(&self) -> [pallas::Base; NUM_RESOURCE] {
        [
            self.public_inputs
                .get_from_index(VP_CIRCUIT_NULLIFIER_ONE_PUBLIC_INPUT_IDX),
            self.public_inputs
                .get_from_index(VP_CIRCUIT_NULLIFIER_TWO_PUBLIC_INPUT_IDX),
        ]
    }

    pub fn get_resource_commitments(&self) -> [ResourceCommitment; NUM_RESOURCE] {
        [
            self.public_inputs
                .get_from_index(VP_CIRCUIT_OUTPUT_CM_ONE_PUBLIC_INPUT_IDX)
                .into(),
            self.public_inputs
                .get_from_index(VP_CIRCUIT_OUTPUT_CM_TWO_PUBLIC_INPUT_IDX)
                .into(),
        ]
    }

    pub fn get_owned_resource_id(&self) -> pallas::Base {
        self.public_inputs
            .get_from_index(VP_CIRCUIT_OWNED_RESOURCE_ID_PUBLIC_INPUT_IDX)
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for VPVerifyingInfo {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        use ff::PrimeField;
        // Write vk
        self.vk.write(writer)?;
        // Write proof
        self.proof.serialize(writer)?;
        // Write public inputs
        for ele in self.public_inputs.inner().iter() {
            writer.write_all(&ele.to_repr())?;
        }
        Ok(())
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for VPVerifyingInfo {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        use ff::PrimeField;
        use std::io;
        // Read vk
        use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
        let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
        let vk = VerifyingKey::read::<_, TrivialValidityPredicateCircuit>(reader, params)?;
        // Read proof
        let proof = Proof::deserialize_reader(reader)?;
        // Read public inputs
        let public_inputs: Vec<_> = (0..VP_CIRCUIT_PUBLIC_INPUT_NUM)
            .map(|_| {
                let bytes = <[u8; 32]>::deserialize_reader(reader)?;
                Option::from(pallas::Base::from_repr(bytes)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "public input not in field")
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(VPVerifyingInfo {
            vk,
            proof,
            public_inputs: public_inputs.into(),
        })
    }
}

#[cfg(feature = "serde")]
fn serde_serialize_verifying_key<S>(
    x: &VerifyingKey<vesta::Affine>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut buf = Vec::new();
    x.write(&mut buf).unwrap();
    s.serialize_bytes(&buf)
}

#[cfg(feature = "serde")]
fn serde_deserialize_verifying_key<'de, D>(d: D) -> Result<VerifyingKey<vesta::Affine>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let buf: Vec<u8> = serde::Deserialize::deserialize(d)?;

    use crate::circuit::vp_examples::TrivialValidityPredicateCircuit;
    let params = SETUP_PARAMS_MAP.get(&VP_CIRCUIT_PARAMS_SIZE).unwrap();
    let vk = VerifyingKey::read::<_, TrivialValidityPredicateCircuit>(&mut buf.as_slice(), params)
        .map_err(|e| Error::custom(format!("Error reading VerifyingKey: {}", e)))?;
    Ok(vk)
}

impl ValidityPredicatePublicInputs {
    pub fn inner(&self) -> &[pallas::Base; VP_CIRCUIT_PUBLIC_INPUT_NUM] {
        &self.0
    }

    pub fn get_from_index(&self, idx: usize) -> pallas::Base {
        assert!(idx < VP_CIRCUIT_PUBLIC_INPUT_NUM);
        self.0[idx]
    }

    pub fn get_public_input_padding(input_len: usize, rseed: &RandomSeed) -> Vec<pallas::Base> {
        assert!(input_len < VP_CIRCUIT_PUBLIC_INPUT_NUM);
        rseed.get_random_padding(VP_CIRCUIT_PUBLIC_INPUT_NUM - input_len)
    }

    // Only pad the custom public inputs, then we can add the actual resource encryption public inputs.
    pub fn get_custom_public_input_padding(
        input_len: usize,
        rseed: &RandomSeed,
    ) -> Vec<pallas::Base> {
        assert!(input_len < VP_CIRCUIT_NOTE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX);
        rseed.get_random_padding(VP_CIRCUIT_NOTE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX - input_len)
    }

    pub fn to_vec(&self) -> Vec<pallas::Base> {
        self.0.to_vec()
    }

    pub fn decrypt(&self, sk: pallas::Base) -> Option<Vec<pallas::Base>> {
        let cipher: NoteCiphertext = self.0[VP_CIRCUIT_NOTE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX
            ..VP_CIRCUIT_NOTE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX + NOTE_ENCRYPTION_CIPHERTEXT_NUM]
            .to_vec()
            .into();
        let sender_pk = pallas::Affine::from_xy(
            self.get_from_index(VP_CIRCUIT_NOTE_ENCRYPTION_PK_X_IDX),
            self.get_from_index(VP_CIRCUIT_NOTE_ENCRYPTION_PK_Y_IDX),
        )
        .unwrap()
        .to_curve();
        let key = SecretKey::from_dh_exchange(&sender_pk, &mod_r_p(sk));
        cipher.decrypt(&key)
    }
}

impl From<Vec<pallas::Base>> for ValidityPredicatePublicInputs {
    fn from(public_input_vec: Vec<pallas::Base>) -> Self {
        ValidityPredicatePublicInputs(
            public_input_vec
                .try_into()
                .expect("public input with incorrect length"),
        )
    }
}

#[derive(Clone, Debug)]
pub struct ValidityPredicateConfig {
    pub advices: [Column<Advice>; 10],
    pub instances: Column<Instance>,
    pub table_idx: TableColumn,
    pub ecc_config: EccConfig<TaigaFixedBases>,
    pub poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    pub get_is_input_resource_flag_config: GetIsInputResourceFlagConfig,
    pub get_owned_resource_variable_config: GetOwnedResourceVariableConfig,
    pub conditional_equal_config: ConditionalEqualConfig,
    pub conditional_select_config: ConditionalSelectConfig,
    pub extended_or_relation_config: ExtendedOrRelationConfig,
    pub add_config: AddConfig,
    pub sub_config: SubConfig,
    pub mul_config: MulConfig,
    pub blake2s_config: Blake2sConfig<pallas::Base>,
    pub note_commit_config: ResourceCommitConfig,
}

impl ValidityPredicateConfig {
    pub fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
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

        let get_owned_resource_variable_config = GetOwnedResourceVariableConfig::configure(
            meta,
            advices[0],
            [advices[1], advices[2], advices[3], advices[4]],
        );

        let get_is_input_resource_flag_config =
            GetIsInputResourceFlagConfig::configure(meta, advices[0], advices[1], advices[2]);

        let conditional_equal_config =
            ConditionalEqualConfig::configure(meta, [advices[0], advices[1], advices[2]]);
        let conditional_select_config =
            ConditionalSelectConfig::configure(meta, [advices[0], advices[1]]);

        let add_config = AddChip::configure(meta, [advices[0], advices[1]]);
        let sub_config = SubChip::configure(meta, [advices[0], advices[1]]);
        let mul_config = MulChip::configure(meta, [advices[0], advices[1]]);

        let extended_or_relation_config =
            ExtendedOrRelationConfig::configure(meta, [advices[0], advices[1], advices[2]]);
        let blake2s_config = Blake2sConfig::configure(meta, advices);
        let note_commit_config = ResourceCommitChip::configure(
            meta,
            advices[0..3].try_into().unwrap(),
            poseidon_config.clone(),
            range_check,
        );
        Self {
            advices,
            instances,
            table_idx,
            ecc_config,
            poseidon_config,
            get_is_input_resource_flag_config,
            get_owned_resource_variable_config,
            conditional_equal_config,
            conditional_select_config,
            extended_or_relation_config,
            add_config,
            sub_config,
            mul_config,
            blake2s_config,
            note_commit_config,
        }
    }
}

pub trait ValidityPredicateVerifyingInfo: DynClone {
    fn get_verifying_info(&self) -> VPVerifyingInfo;
    fn verify_transparently(&self) -> Result<ValidityPredicatePublicInputs, TransactionError>;
    fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey;
}

clone_trait_object!(ValidityPredicateVerifyingInfo);

pub trait ValidityPredicateCircuit: Circuit<pallas::Base> + ValidityPredicateVerifyingInfo {
    // Default implementation, constrains the resources integrity.
    // TODO: how to enforce the constraints in vp circuit?
    fn basic_constraints(
        &self,
        config: ValidityPredicateConfig,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<BasicValidityPredicateVariables, Error> {
        layouter.assign_table(
            || "table_idx",
            |mut table| {
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

        // Construct a note_commit chip
        let note_commit_chip = ResourceCommitChip::construct(config.note_commit_config.clone());

        let input_resources = self.get_input_resources();
        let output_resources = self.get_output_resources();
        let mut input_resource_variables = vec![];
        let mut output_resource_variables = vec![];
        for i in 0..NUM_RESOURCE {
            input_resource_variables.push(check_input_resource(
                layouter.namespace(|| "check input resource"),
                config.advices,
                config.instances,
                note_commit_chip.clone(),
                input_resources[i],
                i * 2,
            )?);

            // The old_nf may not be from above input resource
            let old_nf = assign_free_advice(
                layouter.namespace(|| "old nf"),
                config.advices[0],
                Value::known(output_resources[i].rho.inner()),
            )?;
            output_resource_variables.push(check_output_resource(
                layouter.namespace(|| "check output resource"),
                config.advices,
                config.instances,
                note_commit_chip.clone(),
                output_resources[i],
                old_nf,
                i * 2 + 1,
            )?);
        }

        // Publicize the owned_resource_id
        let owned_resource_id = assign_free_advice(
            layouter.namespace(|| "owned_resource_id"),
            config.advices[0],
            Value::known(self.get_owned_resource_id()),
        )?;
        layouter.constrain_instance(
            owned_resource_id.cell(),
            config.instances,
            VP_CIRCUIT_OWNED_RESOURCE_ID_PUBLIC_INPUT_IDX,
        )?;

        Ok(BasicValidityPredicateVariables {
            owned_resource_id,
            input_resource_variables: input_resource_variables.try_into().unwrap(),
            output_resource_variables: output_resource_variables.try_into().unwrap(),
        })
    }

    // VP designer need to implement the following functions.
    // `get_input_resources` and `get_output_resources` will be used in `basic_constraints` to get the basic resource info.

    // Add custom constraints on basic resource variables and user-defined variables.
    // It should at least contain the default vp commitment
    fn custom_constraints(
        &self,
        config: ValidityPredicateConfig,
        mut layouter: impl Layouter<pallas::Base>,
        _basic_variables: BasicValidityPredicateVariables,
    ) -> Result<(), Error> {
        // Publicize the dynamic vp commitments with default value
        publicize_default_dynamic_vp_commitments(
            &mut layouter,
            config.advices[0],
            config.instances,
        )?;

        Ok(())
    }

    fn get_mandatory_public_inputs(&self) -> Vec<pallas::Base> {
        let mut public_inputs = vec![];
        self.get_input_resources()
            .iter()
            .zip(self.get_output_resources().iter())
            .for_each(|(input_resource, output_resource)| {
                let nf = input_resource.get_nf().unwrap().inner();
                public_inputs.push(nf);
                let cm = output_resource.commitment();
                public_inputs.push(cm.inner());
            });
        public_inputs.push(self.get_owned_resource_id());
        public_inputs
    }
    fn get_input_resources(&self) -> &[Resource; NUM_RESOURCE];
    fn get_output_resources(&self) -> &[Resource; NUM_RESOURCE];
    fn get_public_inputs(&self, rng: impl RngCore) -> ValidityPredicatePublicInputs;
    // The owned_resource_id is the input_resource_nf or the output_resource_cm_x
    // The owned_resource_id is the key to look up the target variables and
    // help determine whether the owned resource is the input resource or not in VP circuit.
    fn get_owned_resource_id(&self) -> pallas::Base;
}

/// BasicValidityPredicateVariables are generally constrained in ValidityPredicateCircuit::basic_constraints
/// and will be used in ValidityPredicateCircuit::custom_constraints
#[derive(Debug, Clone)]
pub struct BasicValidityPredicateVariables {
    pub owned_resource_id: AssignedCell<pallas::Base, pallas::Base>,
    pub input_resource_variables: [InputResourceVariables; NUM_RESOURCE],
    pub output_resource_variables: [OutputResourceVariables; NUM_RESOURCE],
}

#[derive(Debug, Clone)]
pub struct ResourceVariables {
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

// Variables in the input resource
#[derive(Debug, Clone)]
pub struct InputResourceVariables {
    pub nf: AssignedCell<pallas::Base, pallas::Base>,
    pub cm: AssignedCell<pallas::Base, pallas::Base>,
    pub resource_variables: ResourceVariables,
}

// Variables in the out resource
#[derive(Debug, Clone)]
pub struct OutputResourceVariables {
    pub cm: AssignedCell<pallas::Base, pallas::Base>,
    pub resource_variables: ResourceVariables,
}

#[derive(Debug, Clone)]
pub struct ResourceSearchableVariablePair {
    // src_variable is the input_resource_nf or the output_resource_cm_x
    pub src_variable: AssignedCell<pallas::Base, pallas::Base>,
    // target_variable is one of the parameter in the ResourceVariables
    pub target_variable: AssignedCell<pallas::Base, pallas::Base>,
}

impl BasicValidityPredicateVariables {
    pub fn get_owned_resource_id(&self) -> AssignedCell<pallas::Base, pallas::Base> {
        self.owned_resource_id.clone()
    }

    pub fn get_input_resource_nfs(
        &self,
    ) -> [AssignedCell<pallas::Base, pallas::Base>; NUM_RESOURCE] {
        let ret: Vec<_> = self
            .input_resource_variables
            .iter()
            .map(|variables| variables.nf.clone())
            .collect();
        ret.try_into().unwrap()
    }

    pub fn get_output_resource_cms(
        &self,
    ) -> [AssignedCell<pallas::Base, pallas::Base>; NUM_RESOURCE] {
        let ret: Vec<_> = self
            .output_resource_variables
            .iter()
            .map(|variables| variables.cm.clone())
            .collect();
        ret.try_into().unwrap()
    }

    fn get_variable_searchable_pairs(
        &self,
        input_target_variable: impl Fn(
            &InputResourceVariables,
        ) -> AssignedCell<pallas::Base, pallas::Base>,
        output_target_variable: impl Fn(
            &OutputResourceVariables,
        ) -> AssignedCell<pallas::Base, pallas::Base>,
    ) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.input_resource_variables
            .iter()
            .map(|variables| ResourceSearchableVariablePair {
                src_variable: variables.nf.clone(),
                target_variable: input_target_variable(variables),
            })
            .chain(self.output_resource_variables.iter().map(|variables| {
                ResourceSearchableVariablePair {
                    src_variable: variables.cm.clone(),
                    target_variable: output_target_variable(variables),
                }
            }))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    pub fn get_app_vk_searchable_pairs(
        &self,
    ) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.app_vk.clone(),
            |variables| variables.resource_variables.app_vk.clone(),
        )
    }

    pub fn get_app_data_static_searchable_pairs(
        &self,
    ) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.app_data_static.clone(),
            |variables| variables.resource_variables.app_data_static.clone(),
        )
    }

    pub fn get_value_searchable_pairs(&self) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.value.clone(),
            |variables| variables.resource_variables.value.clone(),
        )
    }

    pub fn get_is_merkle_checked_searchable_pairs(
        &self,
    ) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.is_merkle_checked.clone(),
            |variables| variables.resource_variables.is_merkle_checked.clone(),
        )
    }

    pub fn get_app_data_dynamic_searchable_pairs(
        &self,
    ) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.app_data_dynamic.clone(),
            |variables| variables.resource_variables.app_data_dynamic.clone(),
        )
    }

    pub fn get_rho_searchable_pairs(&self) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.rho.clone(),
            |variables| variables.resource_variables.rho.clone(),
        )
    }

    pub fn get_nk_com_searchable_pairs(
        &self,
    ) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.nk_com.clone(),
            |variables| variables.resource_variables.nk_com.clone(),
        )
    }

    pub fn get_psi_searchable_pairs(&self) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.psi.clone(),
            |variables| variables.resource_variables.psi.clone(),
        )
    }

    pub fn get_rcm_searchable_pairs(&self) -> [ResourceSearchableVariablePair; NUM_RESOURCE * 2] {
        self.get_variable_searchable_pairs(
            |variables| variables.resource_variables.rcm.clone(),
            |variables| variables.resource_variables.rcm.clone(),
        )
    }
}

// Default Circuit trait implementation
#[macro_export]
macro_rules! vp_circuit_impl {
    ($name:ident) => {
        impl Circuit<pallas::Base> for $name {
            type Config = ValidityPredicateConfig;
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
    };
}

// Default ValidityPredicateVerifyingInfo trait implementation
#[macro_export]
macro_rules! vp_verifying_info_impl {
    ($name:ident) => {
        impl ValidityPredicateVerifyingInfo for $name {
            fn get_verifying_info(&self) -> VPVerifyingInfo {
                let mut rng = OsRng;
                let params = SETUP_PARAMS_MAP.get(&15).unwrap();
                let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
                let pk = keygen_pk(params, vk.clone(), self).expect("keygen_pk should not fail");
                let public_inputs = self.get_public_inputs(&mut rng);
                let proof = Proof::create(
                    &pk,
                    params,
                    self.clone(),
                    &[public_inputs.inner()],
                    &mut rng,
                )
                .unwrap();
                VPVerifyingInfo {
                    vk,
                    proof,
                    public_inputs,
                }
            }

            fn verify_transparently(
                &self,
            ) -> Result<ValidityPredicatePublicInputs, TransactionError> {
                use halo2_proofs::dev::MockProver;
                let mut rng = OsRng;
                let public_inputs = self.get_public_inputs(&mut rng);
                let prover =
                    MockProver::<pallas::Base>::run(15, self, vec![public_inputs.to_vec()])
                        .unwrap();
                prover.verify().unwrap();
                Ok(public_inputs)
            }

            fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey {
                let params = SETUP_PARAMS_MAP.get(&15).unwrap();
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
    pub public_inputs: Vec<pallas::Base>,
}

#[derive(Debug)]
pub enum VampIRCircuitError {
    MissingAssignment(String),
    SourceParsingError(String),
}

impl VampIRCircuitError {
    fn from_variable_assignment_error(error: VariableAssignmentError) -> Self {
        match error {
            VariableAssignmentError::MissingAssignment(s) => {
                VampIRCircuitError::MissingAssignment(s)
            }
        }
    }
}

impl VampIRValidityPredicateCircuit {
    pub fn from_vamp_ir_source(
        vamp_ir_source: &str,
        named_field_assignments: HashMap<String, Fp>,
    ) -> Result<Self, VampIRCircuitError> {
        let config = Config { quiet: true };
        let parsed_vamp_ir_module =
            parse(vamp_ir_source).map_err(VampIRCircuitError::SourceParsingError)?;
        let vamp_ir_module = compile(
            parsed_vamp_ir_module,
            &PrimeFieldOps::<Fp>::default(),
            &config,
        );
        let mut circuit = Halo2Module::<Fp>::new(Rc::new(vamp_ir_module));
        let params = Params::new(circuit.k);
        let field_assignments = get_circuit_assignments(&circuit.module, &named_field_assignments)
            .map_err(VampIRCircuitError::from_variable_assignment_error)?;

        // Populate variable definitions
        circuit.populate_variables(field_assignments.clone());

        // Get public inputs Fp
        let public_inputs = circuit
            .module
            .pubs
            .iter()
            .map(|inst| field_assignments[&inst.id])
            .collect::<Vec<pallas::Base>>();

        Ok(Self {
            params,
            circuit,
            public_inputs,
        })
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
        let public_inputs = circuit
            .module
            .pubs
            .iter()
            .map(|inst| var_assignments[&inst.id])
            .collect::<Vec<pallas::Base>>();

        Self {
            params,
            circuit,
            public_inputs,
        }
    }
}

impl ValidityPredicateVerifyingInfo for VampIRValidityPredicateCircuit {
    fn get_verifying_info(&self) -> VPVerifyingInfo {
        let mut rng = OsRng;
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        let pk =
            keygen_pk(&self.params, vk.clone(), &self.circuit).expect("keygen_pk should not fail");

        let mut public_inputs = self.public_inputs.clone();
        let rseed = RandomSeed::random(&mut rng);
        public_inputs.extend(ValidityPredicatePublicInputs::get_public_input_padding(
            self.public_inputs.len(),
            &rseed,
        ));

        let proof = Proof::create(
            &pk,
            &self.params,
            self.circuit.clone(),
            &[&public_inputs.to_vec()],
            &mut rng,
        )
        .unwrap();
        VPVerifyingInfo {
            vk,
            proof,
            public_inputs: public_inputs.into(),
        }
    }

    fn verify_transparently(&self) -> Result<ValidityPredicatePublicInputs, TransactionError> {
        use halo2_proofs::dev::MockProver;
        let mut rng = OsRng;
        let mut public_inputs = self.public_inputs.clone();
        let rseed = RandomSeed::random(&mut rng);
        public_inputs.extend(ValidityPredicatePublicInputs::get_public_input_padding(
            self.public_inputs.len(),
            &rseed,
        ));
        let prover =
            MockProver::<pallas::Base>::run(15, &self.circuit, vec![public_inputs.to_vec()])
                .unwrap();
        prover.verify().unwrap();
        Ok(ValidityPredicatePublicInputs::from(public_inputs))
    }

    fn get_vp_vk(&self) -> ValidityPredicateVerifyingKey {
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        ValidityPredicateVerifyingKey::from_vk(vk)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::vp_circuit::{
        ValidityPredicateVerifyingInfo, VampIRValidityPredicateCircuit,
    };
    use num_bigint::BigInt;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use vamp_ir::halo2::synth::make_constant;

    #[ignore]
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
            .verify(
                &vp_info.vk,
                &vp_circuit.params,
                &[vp_info.public_inputs.inner()],
            )
            .unwrap();
    }

    #[test]
    fn test_create_vp_from_invalid_vamp_ir_file() {
        let invalid_vamp_ir_source =
            VampIRValidityPredicateCircuit::from_vamp_ir_source("{aaxxx", HashMap::new());
        assert!(invalid_vamp_ir_source.is_err());
    }

    #[test]
    fn test_create_vp_with_missing_assignment() {
        let missing_x_assignment =
            VampIRValidityPredicateCircuit::from_vamp_ir_source("x = 1;", HashMap::new());
        assert!(missing_x_assignment.is_err());
    }

    #[test]
    fn test_create_vp_with_no_assignment() {
        let zero_constraint =
            VampIRValidityPredicateCircuit::from_vamp_ir_source("0;", HashMap::new());
        assert!(zero_constraint.is_ok());
    }

    #[ignore]
    #[test]
    fn test_create_vp_with_valid_assignment() {
        let x_assignment_circuit = VampIRValidityPredicateCircuit::from_vamp_ir_source(
            "x = 1;",
            HashMap::from([(String::from("x"), make_constant(BigInt::from(1)))]),
        );

        assert!(x_assignment_circuit.is_ok());

        let vp_circuit = x_assignment_circuit.unwrap();
        let vp_info = vp_circuit.get_verifying_info();

        assert!(vp_info
            .proof
            .verify(
                &vp_info.vk,
                &vp_circuit.params,
                &[vp_info.public_inputs.inner()]
            )
            .is_ok());
    }

    #[ignore]
    #[test]
    fn test_create_vp_with_invalid_assignment() {
        let x_assignment_circuit = VampIRValidityPredicateCircuit::from_vamp_ir_source(
            "x = 1;",
            HashMap::from([(String::from("x"), make_constant(BigInt::from(0)))]),
        );

        assert!(x_assignment_circuit.is_ok());

        let vp_circuit = x_assignment_circuit.unwrap();
        let vp_info = vp_circuit.get_verifying_info();

        assert!(vp_info
            .proof
            .verify(
                &vp_info.vk,
                &vp_circuit.params,
                &[vp_info.public_inputs.inner()]
            )
            .is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_vk_serialize() {
        use crate::circuit::{
            vp_circuit::{serde_deserialize_verifying_key, serde_serialize_verifying_key},
            vp_examples::TrivialValidityPredicateCircuit,
        };
        use halo2_proofs::plonk::VerifyingKey;
        use pasta_curves::vesta;
        use serde_json;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct TestStruct {
            #[serde(
                serialize_with = "serde_serialize_verifying_key",
                deserialize_with = "serde_deserialize_verifying_key"
            )]
            vk: VerifyingKey<vesta::Affine>,
        }

        let t = TrivialValidityPredicateCircuit::default().get_vp_vk();

        let a = TestStruct {
            vk: t.get_vk().unwrap(),
        };

        let ser = serde_json::to_string(&a).unwrap();
        let deser: TestStruct = serde_json::from_str(&ser).unwrap();

        let a_bytes = a.vk.to_bytes();
        let deser_bytes = deser.vk.to_bytes();

        assert_eq!(a_bytes, deser_bytes);
    }
}
