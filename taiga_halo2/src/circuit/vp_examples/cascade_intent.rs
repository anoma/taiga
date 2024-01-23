/// The intent is to show how to cascade partial transactions so they can be executed atomically.
/// In this example, Alice wants to spend three(more than the fixed NUM_RESOURCE) different kinds of tokens/resources simultaneously.
/// She needs to distribute the resources to two partial transactions. She can use the intent to cascade the partial transactions.
/// In the first partial transaction, she spends two resources and creates a cascade intent resource to encode and check the third resource info.
/// In the second partial transaction, she spends the cascade resource and the third resource.
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            assign_free_advice,
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
        vp_bytecode::{ValidityPredicateByteCode, ValidityPredicateRepresentation},
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP},
    error::TransactionError,
    nullifier::Nullifier,
    proof::Proof,
    resource::{RandomSeed, Resource},
    utils::read_base_field,
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
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
    pub static ref CASCADE_INTENT_VK: ValidityPredicateVerifyingKey =
        CascadeIntentValidityPredicateCircuit::default().get_vp_vk();
    pub static ref COMPRESSED_CASCADE_INTENT_VK: pallas::Base = CASCADE_INTENT_VK.get_compressed();
}

// CascadeIntentValidityPredicateCircuit
#[derive(Clone, Debug, Default)]
pub struct CascadeIntentValidityPredicateCircuit {
    pub owned_resource_id: pallas::Base,
    pub input_resources: [Resource; NUM_RESOURCE],
    pub output_resources: [Resource; NUM_RESOURCE],
    // use the resource commitment to identify the resource.
    pub cascade_resource_cm: pallas::Base,
}

impl CascadeIntentValidityPredicateCircuit {
    // We can encode at most three resources to label if needed.
    pub fn encode_label(cascade_resource_cm: pallas::Base) -> pallas::Base {
        cascade_resource_cm
    }

    pub fn to_bytecode(&self) -> ValidityPredicateByteCode {
        ValidityPredicateByteCode::new(
            ValidityPredicateRepresentation::CascadeIntent,
            self.to_bytes(),
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self).unwrap()
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Self {
        BorshDeserialize::deserialize(&mut bytes.as_ref()).unwrap()
    }
}

impl ValidityPredicateCircuit for CascadeIntentValidityPredicateCircuit {
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        basic_variables: BasicValidityPredicateVariables,
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

        // Publicize the dynamic vp commitments with default value
        publicize_default_dynamic_vp_commitments(
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

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
        let default_vp_cm: [pallas::Base; 2] =
            ValidityPredicateCommitment::default().to_public_inputs();
        public_inputs.extend(default_vp_cm);
        public_inputs.extend(default_vp_cm);
        let padding = ValidityPredicatePublicInputs::get_public_input_padding(
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

vp_circuit_impl!(CascadeIntentValidityPredicateCircuit);
vp_verifying_info_impl!(CascadeIntentValidityPredicateCircuit);

impl BorshSerialize for CascadeIntentValidityPredicateCircuit {
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

impl BorshDeserialize for CascadeIntentValidityPredicateCircuit {
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
    let label = CascadeIntentValidityPredicateCircuit::encode_label(cascade_resource_cm);
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
fn test_halo2_cascade_intent_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
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

        CascadeIntentValidityPredicateCircuit {
            owned_resource_id: input_resources[0].get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            cascade_resource_cm,
        }
    };

    // Test serialization
    let circuit = {
        let circuit_bytes = circuit.to_bytes();
        CascadeIntentValidityPredicateCircuit::from_bytes(&circuit_bytes)
    };

    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover = MockProver::<pallas::Base>::run(
        VP_CIRCUIT_PARAMS_SIZE,
        &circuit,
        vec![public_inputs.to_vec()],
    )
    .unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
