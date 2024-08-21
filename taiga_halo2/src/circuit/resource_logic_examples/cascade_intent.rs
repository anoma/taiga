/// This example is to demonstrate how to cascade partial transactions for
/// atomic execution by the cascade intent. In this example, Alice wants to
/// simultaneously spend three different kinds of tokens/resources (more than
/// the fixed NUM_RESOURCE). She needs to distribute the resources into two
/// partial transactions and can utilize a cascade intent resource for encoding
/// and verifying the third resource information in the first transaction. In
/// the second transaction, she spends both the cascade resource and the third
/// resource.
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{
            assign_free_advice,
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
        resource_logic_bytecode::{ResourceLogicByteCode, ResourceLogicRepresentation},
        resource_logic_circuit::{
            BasicResourceLogicVariables, ResourceLogicCircuit, ResourceLogicConfig,
            ResourceLogicPublicInputs, ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait,
        },
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    nullifier::Nullifier,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
    utils::read_base_field,
};
use borsh::{BorshDeserialize, BorshSerialize};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::{group::ff::PrimeField, pallas};
use rand::rngs::OsRng;
use rand::RngCore;

lazy_static! {
    pub static ref CASCADE_INTENT_VK: ResourceLogicVerifyingKey =
        CascadeIntentResourceLogicCircuit::default().get_resource_logic_vk();
    pub static ref COMPRESSED_CASCADE_INTENT_VK: pallas::Base = CASCADE_INTENT_VK.get_compressed();
}

// CascadeIntentResourceLogicCircuit
#[derive(Clone, Debug, Default)]
pub struct CascadeIntentResourceLogicCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    // use the resource commitment to identify the resource.
    pub cascade_resource_cm: pallas::Base,
}

impl CascadeIntentResourceLogicCircuit {
    // We can encode at most three resources to label if needed.
    pub fn encode_label(cascade_resource_cm: pallas::Base) -> pallas::Base {
        cascade_resource_cm
    }

    pub fn to_bytecode(&self) -> ResourceLogicByteCode {
        ResourceLogicByteCode::new(ResourceLogicRepresentation::CascadeIntent, self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap()
    }
}

impl ResourceLogicCircuit for CascadeIntentResourceLogicCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicResourceLogicVariables,
    ) -> Result<(), Error> {
        let owned_resource_id = basic_variables.get_owned_resource_id();
        let is_input_resource = get_is_input_resource_flag(
            config.get_is_input_resource_flag_config,
            layouter.namespace(|| "get is_input_resource_flag"),
            &owned_resource_id,
            &basic_variables.get_input_resource_nfs(),
            &basic_variables.get_output_resource_cms(),
        )?;

        // If the number of cascade resources is more than one, encode them.
        let cascade_resource_cm = assign_free_advice(
            layouter.namespace(|| "witness cascade_resource_cm"),
            config.advices[0],
            Value::known(self.cascade_resource_cm),
        )?;

        // search target resource and get the intent label
        let label = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource label"),
            &owned_resource_id,
            &basic_variables.get_label_searchable_pairs(),
        )?;

        // check the label of intent resource
        layouter.assign_region(
            || "check label",
            |mut region| region.constrain_equal(cascade_resource_cm.cell(), label.cell()),
        )?;

        // check the cascade resource
        layouter.assign_region(
            || "conditional equal: check the cascade resource",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_resource,
                    &label,
                    &basic_variables.input_resource_variables[1].cm,
                    0,
                    &mut region,
                )
            },
        )?;

        // Publicize the dynamic resource_logic commitments with default value
        publicize_default_dynamic_resource_logic_commitments(
            &mut layouter,
            config.advices[0],
            config.instances,
        )?;

        Ok(())
    }

    fn get_input_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.input_resources
    }

    fn get_output_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.output_resources
    }

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ResourceLogicPublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let default_resource_logic_cm: [pallas::Base; 2] =
            ResourceLogicCommitment::default().to_public_inputs();
        public_inputs.extend(default_resource_logic_cm);
        public_inputs.extend(default_resource_logic_cm);
        let padding = ResourceLogicPublicInputs::get_public_input_padding(
            public_inputs.len(),
            &RandomSeed::random(&mut rng),
        );
        public_inputs.extend(padding);
        public_inputs.into()
    }

    fn get_owned_resource_id(&self) -> pallas::Base {
        self.owned_resource_id
    }
}

resource_logic_circuit_impl!(CascadeIntentResourceLogicCircuit);
resource_logic_verifying_info_impl!(CascadeIntentResourceLogicCircuit);

impl BorshSerialize for CascadeIntentResourceLogicCircuit {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.owned_resource_id.to_repr())?;
        for input in self.input_resources.iter() {
            input.serialize(writer)?;
        }

        for output in self.output_resources.iter() {
            output.serialize(writer)?;
        }

        writer.write_all(&self.cascade_resource_cm.to_repr())?;
        Ok(())
    }
}

impl BorshDeserialize for CascadeIntentResourceLogicCircuit {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let owned_resource_id = read_base_field(reader)?;
        let input_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let output_resources: Vec<_> = (0..NUM_RESOURCE)
            .map(|_| Resource::deserialize_reader(reader))
            .collect::<Result<_, _>>()?;
        let cascade_resource_cm = read_base_field(reader)?;
        Ok(Self {
            owned_resource_id,
            input_resources: input_resources.try_into().unwrap(),
            output_resources: output_resources.try_into().unwrap(),
            cascade_resource_cm,
        })
    }
}

pub fn create_intent_resource<R: RngCore>(
    mut rng: R,
    cascade_resource_cm: pallas::Base,
    nk: pallas::Base,
) -> Resource {
    let label = CascadeIntentResourceLogicCircuit::encode_label(cascade_resource_cm);
    let rseed = pallas::Base::random(&mut rng);
    let nonce = Nullifier::random(&mut rng);
    Resource::new_input_resource(
        *COMPRESSED_CASCADE_INTENT_VK,
        label,
        pallas::Base::zero(),
        1u64,
        nk,
        nonce,
        true,
        rseed,
    )
}

#[test]
fn test_halo2_cascade_intent_resource_logic_circuit() {
    use crate::constant::RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE;
    use crate::resource::tests::random_resource;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let cascade_input_resource = random_resource(&mut rng);
        let cascade_resource_cm = cascade_input_resource.commitment().inner();
        let nk = pallas::Base::random(&mut rng);
        let intent_resource = create_intent_resource(&mut rng, cascade_resource_cm, nk);
        let input_resources = [intent_resource, cascade_input_resource];
        let output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));

        CascadeIntentResourceLogicCircuit {
            owned_resource_id: input_resources[0].get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            cascade_resource_cm,
        }
    };

    // Test serialization
    let circuit = {
        let circuit_bytes = circuit.to_bytes();
        CascadeIntentResourceLogicCircuit::from_bytes(&circuit_bytes)
    };

    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover = MockProver::<pallas::Base>::run(
        RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE,
        &circuit,
        vec![public_inputs.to_vec()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
