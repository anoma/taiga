use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        blake2s::Blake2sConfig,
        gadgets::{
            add::{AddChip, AddConfig},
            conditional_equal::ConditionalEqualConfig,
            conditional_select::ConditionalSelectConfig,
            extended_or_relation::ExtendedOrRelationConfig,
            mul::{MulChip, MulConfig},
            sub::{SubChip, SubConfig},
        },
        integrity::load_resource,
        merkle_circuit::{MerklePoseidonChip, MerklePoseidonConfig},
        resource_commitment::{ResourceCommitChip, ResourceCommitConfig},
        vamp_ir_utils::{get_circuit_assignments, parse, VariableAssignmentError},
    },
    constant::{
        TaigaFixedBases, RESOURCE_ENCRYPTION_CIPHERTEXT_NUM, RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
        RESOURCE_LOGIC_CIRCUIT_PUBLIC_INPUT_NUM,
        RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PK_X_IDX,
        RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PK_Y_IDX,
        RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX,
        RESOURCE_LOGIC_CIRCUIT_RESOURCE_MERKLE_ROOT_IDX,
        RESOURCE_LOGIC_CIRCUIT_SELF_RESOURCE_ID_IDX, SETUP_PARAMS_MAP,
    },
    error::TransactionError,
    proof::Proof,
    resource::RandomSeed,
    resource_encryption::{ResourceCiphertext, SecretKey},
    resource_logic_vk::ResourceLogicVerifyingKey,
    resource_tree::ResourceExistenceWitness,
    utils::mod_r_p,
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

pub type ResourceLogic = dyn ResourceLogicVerifyingInfoTrait;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceLogicVerifyingInfo {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serde_serialize_verifying_key",
            deserialize_with = "serde_deserialize_verifying_key"
        )
    )]
    pub vk: VerifyingKey<vesta::Affine>,
    pub proof: Proof,
    pub public_inputs: ResourceLogicPublicInputs,
}

#[cfg(feature = "nif")]
rustler::atoms! {verifying_info}

#[cfg(feature = "nif")]
impl Encoder for ResourceLogicVerifyingInfo {
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
impl<'a> Decoder<'a> for ResourceLogicVerifyingInfo {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let (term, vk, proof, public_inputs): (
            atom::Atom,
            Vec<u8>,
            Proof,
            ResourceLogicPublicInputs,
        ) = term.decode()?;
        if term == verifying_info() {
            use crate::circuit::resource_logic_examples::TrivialResourceLogicCircuit;
            let params = SETUP_PARAMS_MAP
                .get(&RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE)
                .unwrap();
            let vk = VerifyingKey::from_bytes::<TrivialResourceLogicCircuit>(&vk, params)
                .map_err(|_e| rustler::Error::Atom("failure to decode"))?;
            Ok(ResourceLogicVerifyingInfo {
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
pub struct ResourceLogicPublicInputs([pallas::Base; RESOURCE_LOGIC_CIRCUIT_PUBLIC_INPUT_NUM]);

#[cfg(feature = "nif")]
impl Encoder for ResourceLogicPublicInputs {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.0.to_vec().encode(env)
    }
}

#[cfg(feature = "nif")]
impl<'a> Decoder<'a> for ResourceLogicPublicInputs {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        let val: Vec<pallas::Base> = Decoder::decode(term)?;
        Ok(val.into())
    }
}

impl ResourceLogicVerifyingInfo {
    pub fn verify(&self) -> Result<(), Error> {
        let params = SETUP_PARAMS_MAP
            .get(&RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE)
            .unwrap();
        self.proof
            .verify(&self.vk, params, &[self.public_inputs.inner()])
    }

    pub fn get_resource_merkle_root(&self) -> pallas::Base {
        self.public_inputs
            .get_from_index(RESOURCE_LOGIC_CIRCUIT_RESOURCE_MERKLE_ROOT_IDX)
    }

    pub fn get_self_resource_id(&self) -> pallas::Base {
        self.public_inputs
            .get_from_index(RESOURCE_LOGIC_CIRCUIT_SELF_RESOURCE_ID_IDX)
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for ResourceLogicVerifyingInfo {
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
impl BorshDeserialize for ResourceLogicVerifyingInfo {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Read vk
        use crate::circuit::resource_logic_examples::TrivialResourceLogicCircuit;
        use crate::utils::read_base_field;
        let params = SETUP_PARAMS_MAP
            .get(&RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE)
            .unwrap();
        let vk = VerifyingKey::read::<_, TrivialResourceLogicCircuit>(reader, params)?;
        // Read proof
        let proof = Proof::deserialize_reader(reader)?;
        // Read public inputs
        let public_inputs: Vec<_> = (0..RESOURCE_LOGIC_CIRCUIT_PUBLIC_INPUT_NUM)
            .map(|_| read_base_field(reader))
            .collect::<Result<_, _>>()?;
        Ok(ResourceLogicVerifyingInfo {
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

    use crate::circuit::resource_logic_examples::TrivialResourceLogicCircuit;
    let params = SETUP_PARAMS_MAP
        .get(&RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE)
        .unwrap();
    let vk = VerifyingKey::read::<_, TrivialResourceLogicCircuit>(&mut buf.as_slice(), params)
        .map_err(|e| Error::custom(format!("Error reading VerifyingKey: {}", e)))?;
    Ok(vk)
}

impl ResourceLogicPublicInputs {
    pub fn inner(&self) -> &[pallas::Base; RESOURCE_LOGIC_CIRCUIT_PUBLIC_INPUT_NUM] {
        &self.0
    }

    pub fn get_from_index(&self, idx: usize) -> pallas::Base {
        assert!(idx < RESOURCE_LOGIC_CIRCUIT_PUBLIC_INPUT_NUM);
        self.0[idx]
    }

    pub fn get_public_input_padding(input_len: usize, rseed: &RandomSeed) -> Vec<pallas::Base> {
        assert!(input_len < RESOURCE_LOGIC_CIRCUIT_PUBLIC_INPUT_NUM);
        rseed.get_random_padding(RESOURCE_LOGIC_CIRCUIT_PUBLIC_INPUT_NUM - input_len)
    }

    // Only pad the custom public inputs, then we can add the actual resource encryption public inputs.
    pub fn get_custom_public_input_padding(
        input_len: usize,
        rseed: &RandomSeed,
    ) -> Vec<pallas::Base> {
        assert!(input_len < RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX);
        rseed.get_random_padding(
            RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX - input_len,
        )
    }

    pub fn to_vec(&self) -> Vec<pallas::Base> {
        self.0.to_vec()
    }

    pub fn decrypt(&self, sk: pallas::Base) -> Option<Vec<pallas::Base>> {
        let cipher: ResourceCiphertext = self.0
            [RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX
                ..RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PUBLIC_INPUT_BEGIN_IDX
                    + RESOURCE_ENCRYPTION_CIPHERTEXT_NUM]
            .to_vec()
            .into();
        let sender_pk = pallas::Affine::from_xy(
            self.get_from_index(RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PK_X_IDX),
            self.get_from_index(RESOURCE_LOGIC_CIRCUIT_RESOURCE_ENCRYPTION_PK_Y_IDX),
        )
        .unwrap()
        .to_curve();
        let key = SecretKey::from_dh_exchange(&sender_pk, &mod_r_p(sk));
        cipher.decrypt(&key)
    }
}

impl From<Vec<pallas::Base>> for ResourceLogicPublicInputs {
    fn from(public_input_vec: Vec<pallas::Base>) -> Self {
        ResourceLogicPublicInputs(
            public_input_vec
                .try_into()
                .expect("public input with incorrect length"),
        )
    }
}

#[derive(Clone, Debug)]
pub struct ResourceLogicConfig {
    pub advices: [Column<Advice>; 10],
    pub instances: Column<Instance>,
    pub table_idx: TableColumn,
    pub ecc_config: EccConfig<TaigaFixedBases>,
    pub poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    pub merkle_config: MerklePoseidonConfig,
    pub conditional_equal_config: ConditionalEqualConfig,
    pub conditional_select_config: ConditionalSelectConfig,
    pub extended_or_relation_config: ExtendedOrRelationConfig,
    pub add_config: AddConfig,
    pub sub_config: SubConfig,
    pub mul_config: MulConfig,
    pub blake2s_config: Blake2sConfig<pallas::Base>,
    pub resource_commit_config: ResourceCommitConfig,
}

impl ResourceLogicConfig {
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
        let resource_commit_config = ResourceCommitChip::configure(
            meta,
            advices[0..3].try_into().unwrap(),
            poseidon_config.clone(),
            range_check,
        );

        let merkle_config = MerklePoseidonChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            poseidon_config.clone(),
        );

        Self {
            advices,
            instances,
            table_idx,
            ecc_config,
            poseidon_config,
            merkle_config,
            conditional_equal_config,
            conditional_select_config,
            extended_or_relation_config,
            add_config,
            sub_config,
            mul_config,
            blake2s_config,
            resource_commit_config,
        }
    }
}

pub trait ResourceLogicVerifyingInfoTrait: DynClone {
    fn get_verifying_info(&self) -> ResourceLogicVerifyingInfo;
    fn verify_transparently(&self) -> Result<ResourceLogicPublicInputs, TransactionError>;
    fn get_resource_logic_vk(&self) -> ResourceLogicVerifyingKey;
}

clone_trait_object!(ResourceLogicVerifyingInfoTrait);

pub trait ResourceLogicCircuit: Circuit<pallas::Base> + ResourceLogicVerifyingInfoTrait {
    // Load self resource and return self_resource and resource_merkle_root
    // TODO: how to enforce the constraints in resource_logic circuit?
    fn basic_constraints(
        &self,
        config: ResourceLogicConfig,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<ResourceStatus, Error> {
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

        // Construct a merkle chip
        let merkle_chip = MerklePoseidonChip::construct(config.merkle_config);
        // Construct a resource_commit chip
        let resource_commit_chip =
            ResourceCommitChip::construct(config.resource_commit_config.clone());

        // Load self_resource
        let self_resource_status = load_resource(
            layouter.namespace(|| "load self resource"),
            config.advices,
            resource_commit_chip,
            config.conditional_select_config,
            merkle_chip,
            &self.get_self_resource(),
        )?;

        // Publicize the resource_merkle_root
        layouter.constrain_instance(
            self_resource_status.resource_merkle_root.cell(),
            config.instances,
            RESOURCE_LOGIC_CIRCUIT_RESOURCE_MERKLE_ROOT_IDX,
        )?;

        // Publicize the self resource id
        layouter.constrain_instance(
            self_resource_status.identity.cell(),
            config.instances,
            RESOURCE_LOGIC_CIRCUIT_SELF_RESOURCE_ID_IDX,
        )?;

        Ok(self_resource_status)
    }

    // Add custom constraints on basic resource variables and user-defined variables.
    // It should at least contain the default resource_logic commitment
    fn custom_constraints(
        &self,
        config: ResourceLogicConfig,
        mut layouter: impl Layouter<pallas::Base>,
        _self_resource: ResourceStatus,
    ) -> Result<(), Error> {
        // Publicize the dynamic resource_logic commitments with default value
        publicize_default_dynamic_resource_logic_commitments(
            &mut layouter,
            config.advices[0],
            config.instances,
        )?;

        Ok(())
    }

    fn get_mandatory_public_inputs(&self) -> Vec<pallas::Base> {
        let resource_witness = self.get_self_resource();
        let root = resource_witness.get_root();
        let id = resource_witness.get_identity();
        vec![root, id]
    }

    fn get_public_inputs(&self, rng: impl RngCore) -> ResourceLogicPublicInputs;

    fn get_self_resource(&self) -> ResourceExistenceWitness;
}

#[derive(Debug, Clone)]
pub struct ResourceStatus {
    pub resource_merkle_root: AssignedCell<pallas::Base, pallas::Base>,
    pub is_input: AssignedCell<pallas::Base, pallas::Base>,
    pub identity: AssignedCell<pallas::Base, pallas::Base>, // nf or cm
    pub resource: ResourceVariables,
}

#[derive(Debug, Clone)]
pub struct ResourceVariables {
    pub logic: AssignedCell<pallas::Base, pallas::Base>,
    pub label: AssignedCell<pallas::Base, pallas::Base>,
    pub quantity: AssignedCell<pallas::Base, pallas::Base>,
    pub is_ephemeral: AssignedCell<pallas::Base, pallas::Base>,
    pub value: AssignedCell<pallas::Base, pallas::Base>,
    pub nonce: AssignedCell<pallas::Base, pallas::Base>,
    pub npk: AssignedCell<pallas::Base, pallas::Base>,
    pub rseed: AssignedCell<pallas::Base, pallas::Base>,
}

// Variables in the input resource
#[derive(Debug, Clone)]
pub struct InputResourceVariables {
    pub nf: AssignedCell<pallas::Base, pallas::Base>,
    pub cm: AssignedCell<pallas::Base, pallas::Base>,
    pub resource_variables: ResourceVariables,
}

// Default Circuit trait implementation
#[macro_export]
macro_rules! resource_logic_circuit_impl {
    ($name:ident) => {
        impl Circuit<pallas::Base> for $name {
            type Config = ResourceLogicConfig;
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
                let self_resource = self.basic_constraints(
                    config.clone(),
                    layouter.namespace(|| "basic constraints"),
                )?;
                self.custom_constraints(
                    config,
                    layouter.namespace(|| "custom constraints"),
                    self_resource,
                )?;
                Ok(())
            }
        }
    };
}

// Default ResourceLogicVerifyingInfoTrait trait implementation
#[macro_export]
macro_rules! resource_logic_verifying_info_impl {
    ($name:ident) => {
        impl ResourceLogicVerifyingInfoTrait for $name {
            fn get_verifying_info(&self) -> ResourceLogicVerifyingInfo {
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
                ResourceLogicVerifyingInfo {
                    vk,
                    proof,
                    public_inputs,
                }
            }

            fn verify_transparently(&self) -> Result<ResourceLogicPublicInputs, TransactionError> {
                use halo2_proofs::dev::MockProver;
                let mut rng = OsRng;
                let public_inputs = self.get_public_inputs(&mut rng);
                let prover =
                    MockProver::<pallas::Base>::run(15, self, vec![public_inputs.to_vec()])
                        .unwrap();
                prover.verify().unwrap();
                Ok(public_inputs)
            }

            fn get_resource_logic_vk(&self) -> ResourceLogicVerifyingKey {
                let params = SETUP_PARAMS_MAP.get(&15).unwrap();
                let vk = keygen_vk(params, self).expect("keygen_vk should not fail");
                ResourceLogicVerifyingKey::from_vk(vk)
            }
        }
    };
}

#[derive(Clone)]
pub struct VampIRResourceLogicCircuit {
    // TODO: vamp_ir doesn't support to set the params size manually, add the params here temporarily.
    // remove the params once we can set it as RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE in vamp_ir.
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

impl VampIRResourceLogicCircuit {
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

impl ResourceLogicVerifyingInfoTrait for VampIRResourceLogicCircuit {
    fn get_verifying_info(&self) -> ResourceLogicVerifyingInfo {
        let mut rng = OsRng;
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        let pk =
            keygen_pk(&self.params, vk.clone(), &self.circuit).expect("keygen_pk should not fail");

        let mut public_inputs = self.public_inputs.clone();
        let rseed = RandomSeed::random(&mut rng);
        public_inputs.extend(ResourceLogicPublicInputs::get_public_input_padding(
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
        ResourceLogicVerifyingInfo {
            vk,
            proof,
            public_inputs: public_inputs.into(),
        }
    }

    fn verify_transparently(&self) -> Result<ResourceLogicPublicInputs, TransactionError> {
        use halo2_proofs::dev::MockProver;
        let mut rng = OsRng;
        let mut public_inputs = self.public_inputs.clone();
        let rseed = RandomSeed::random(&mut rng);
        public_inputs.extend(ResourceLogicPublicInputs::get_public_input_padding(
            self.public_inputs.len(),
            &rseed,
        ));
        let prover =
            MockProver::<pallas::Base>::run(15, &self.circuit, vec![public_inputs.to_vec()])
                .unwrap();
        prover.verify().unwrap();
        Ok(ResourceLogicPublicInputs::from(public_inputs))
    }

    fn get_resource_logic_vk(&self) -> ResourceLogicVerifyingKey {
        let vk = keygen_vk(&self.params, &self.circuit).expect("keygen_vk should not fail");
        ResourceLogicVerifyingKey::from_vk(vk)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::resource_logic_circuit::{
        ResourceLogicVerifyingInfoTrait, VampIRResourceLogicCircuit,
    };
    use num_bigint::BigInt;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use vamp_ir::halo2::synth::make_constant;

    #[ignore]
    #[test]
    fn test_create_resource_logic_from_vamp_ir_file() {
        let vamp_ir_circuit_file = PathBuf::from("./src/circuit/vamp_ir_circuits/pyth.pir");
        let inputs_file = PathBuf::from("./src/circuit/vamp_ir_circuits/pyth.inputs");
        let resource_logic_circuit =
            VampIRResourceLogicCircuit::from_vamp_ir_file(&vamp_ir_circuit_file, &inputs_file);

        // generate proof and instance
        let resource_logic_info = resource_logic_circuit.get_verifying_info();

        // verify the proof
        // TODO: use the resource_logic_info.verify() instead. resource_logic_info.verify() doesn't work now because it uses the fixed RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE params.
        resource_logic_info
            .proof
            .verify(
                &resource_logic_info.vk,
                &resource_logic_circuit.params,
                &[resource_logic_info.public_inputs.inner()],
            )
            .unwrap();
    }

    #[test]
    fn test_create_resource_logic_from_invalid_vamp_ir_file() {
        let invalid_vamp_ir_source =
            VampIRResourceLogicCircuit::from_vamp_ir_source("{aaxxx", HashMap::new());
        assert!(invalid_vamp_ir_source.is_err());
    }

    #[test]
    fn test_create_resource_logic_with_missing_assignment() {
        let missing_x_assignment =
            VampIRResourceLogicCircuit::from_vamp_ir_source("x = 1;", HashMap::new());
        assert!(missing_x_assignment.is_err());
    }

    #[test]
    fn test_create_resource_logic_with_no_assignment() {
        let zero_constraint = VampIRResourceLogicCircuit::from_vamp_ir_source("0;", HashMap::new());
        assert!(zero_constraint.is_ok());
    }

    #[ignore]
    #[test]
    fn test_create_resource_logic_with_valid_assignment() {
        let x_assignment_circuit = VampIRResourceLogicCircuit::from_vamp_ir_source(
            "x = 1;",
            HashMap::from([(String::from("x"), make_constant(BigInt::from(1)))]),
        );

        assert!(x_assignment_circuit.is_ok());

        let resource_logic_circuit = x_assignment_circuit.unwrap();
        let resource_logic_info = resource_logic_circuit.get_verifying_info();

        assert!(resource_logic_info
            .proof
            .verify(
                &resource_logic_info.vk,
                &resource_logic_circuit.params,
                &[resource_logic_info.public_inputs.inner()]
            )
            .is_ok());
    }

    #[ignore]
    #[test]
    fn test_create_resource_logic_with_invalid_assignment() {
        let x_assignment_circuit = VampIRResourceLogicCircuit::from_vamp_ir_source(
            "x = 1;",
            HashMap::from([(String::from("x"), make_constant(BigInt::from(0)))]),
        );

        assert!(x_assignment_circuit.is_ok());

        let resource_logic_circuit = x_assignment_circuit.unwrap();
        let resource_logic_info = resource_logic_circuit.get_verifying_info();

        assert!(resource_logic_info
            .proof
            .verify(
                &resource_logic_info.vk,
                &resource_logic_circuit.params,
                &[resource_logic_info.public_inputs.inner()]
            )
            .is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_vk_serialize() {
        use crate::circuit::{
            resource_logic_circuit::{
                serde_deserialize_verifying_key, serde_serialize_verifying_key,
            },
            resource_logic_examples::TrivialResourceLogicCircuit,
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

        let t = TrivialResourceLogicCircuit::default().get_resource_logic_vk();

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
