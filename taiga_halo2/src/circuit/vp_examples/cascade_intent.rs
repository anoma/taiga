/// The intent is to show how to cascade partial transactions so they can be executed atomically.
/// In this example, Alice wants to spend three(more than the fixed NUM_RESOURCE) different kinds of tokens/resources simultaneously.
/// She needs to distribute the resources to two partial transactions. She can use the intent to cascade the partial transactions.
/// In the first partial transaction, she spends two resources and creates a cascade intent resource to encode and check the third resource info.
/// In the sencond partial transaction, she spends the cascade resource and the third resource.
///
use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            assign_free_advice,
            target_resource_variable::{get_is_input_resource_flag, get_owned_resource_variable},
        },
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
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use pasta_curves::pallas;
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
    pub cascade_note_cm: pallas::Base,
}

impl CascadeIntentValidityPredicateCircuit {
    // We can encode at most three resources to app_data_static if needed.
    pub fn encode_app_data_static(cascade_note_cm: pallas::Base) -> pallas::Base {
        cascade_note_cm
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
        let cascade_note_cm = assign_free_advice(
            layouter.namespace(|| "witness cascade_note_cm"),
            config.advices[0],
            Value::known(self.cascade_note_cm),
        )?;

        // search target resource and get the intent app_static_data
        let app_data_static = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource app_data_static"),
            &owned_resource_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // check the app_data_static of intent resource
        layouter.assign_region(
            || "check app_data_static",
            |mut region| region.constrain_equal(cascade_note_cm.cell(), app_data_static.cell()),
        )?;

        // check the cascade resource
        layouter.assign_region(
            || "conditional equal: check the cascade resource",
            |mut region| {
                config.conditional_equal_config.assign_region(
                    &is_input_resource,
                    &app_data_static,
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

pub fn create_intent_resource<R: RngCore>(
    mut rng: R,
    cascade_note_cm: pallas::Base,
    nk: pallas::Base,
) -> Resource {
    let app_data_static =
        CascadeIntentValidityPredicateCircuit::encode_app_data_static(cascade_note_cm);
    let rseed = RandomSeed::random(&mut rng);
    let rho = Nullifier::random(&mut rng);
    Resource::new_input_resource(
        *COMPRESSED_CASCADE_INTENT_VK,
        app_data_static,
        pallas::Base::zero(),
        1u64,
        nk,
        rho,
        false,
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
        let cascade_note_cm = cascade_input_resource.commitment().inner();
        let nk = pallas::Base::random(&mut rng);
        let intent_resource = create_intent_resource(&mut rng, cascade_note_cm, nk);
        let input_resources = [intent_resource, cascade_input_resource];
        let output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));

        CascadeIntentValidityPredicateCircuit {
            owned_resource_id: input_resources[0].get_nf().unwrap().inner(),
            input_resources,
            output_resources,
            cascade_note_cm,
        }
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
