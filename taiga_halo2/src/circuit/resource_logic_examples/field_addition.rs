use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_resource_logic_commitments,
        gadgets::{
            add::{AddChip, AddInstructions},
            assign_free_advice,
        },
        resource_logic_circuit::{
            BasicResourceLogicVariables, ResourceLogicCircuit, ResourceLogicConfig,
            ResourceLogicPublicInputs, ResourceLogicVerifyingInfo, ResourceLogicVerifyingInfoTrait,
        },
    },
    constant::{
        NUM_RESOURCE, RESOURCE_LOGIC_CIRCUIT_CUSTOM_PUBLIC_INPUT_BEGIN_IDX, SETUP_PARAMS_MAP,
    },
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    resource_logic_commitment::ResourceLogicCommitment,
    resource_logic_vk::ResourceLogicVerifyingKey,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

// FieldAdditionResourceLogicCircuit with a trivial constraint a + b = c.
#[derive(Clone, Debug, Default)]
struct FieldAdditionResourceLogicCircuit {
    self_resource_id: pallas::Base,
    input_resources: [Resource; NUM_RESOURCE],
    output_resources: [Resource; NUM_RESOURCE],
    a: pallas::Base,
    b: pallas::Base,
}

impl ResourceLogicCircuit for FieldAdditionResourceLogicCircuit {
    // Add custom constraints
    // Resource: the trivial resource_logic doesn't constrain on input_resource_variables and output_resource_variables
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        _basic_variables: BasicResourceLogicVariables,
    ) -> Result<(), Error> {
        let a = assign_free_advice(
            layouter.namespace(|| "witness a"),
            config.advices[0],
            Value::known(self.a),
        )?;

        let b = assign_free_advice(
            layouter.namespace(|| "witness b"),
            config.advices[1],
            Value::known(self.b),
        )?;

        let add_chip = AddChip::<pallas::Base>::construct(config.add_config, ());

        let c = add_chip.add(layouter.namespace(|| "a + b = c"), &a, &b)?;

        // Publicize c
        layouter.constrain_instance(
            c.cell(),
            config.instances,
            RESOURCE_LOGIC_CIRCUIT_CUSTOM_PUBLIC_INPUT_BEGIN_IDX,
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
        public_inputs.push(self.a + self.b);
        let padding = ResourceLogicPublicInputs::get_public_input_padding(
            public_inputs.len(),
            &RandomSeed::random(&mut rng),
        );
        public_inputs.extend(padding);
        public_inputs.into()
    }

    fn get_self_resource_id(&self) -> pallas::Base {
        self.self_resource_id
    }
}

resource_logic_circuit_impl!(FieldAdditionResourceLogicCircuit);
resource_logic_verifying_info_impl!(FieldAdditionResourceLogicCircuit);

#[test]
fn test_halo2_addition_resource_logic_circuit() {
    use crate::constant::RESOURCE_LOGIC_CIRCUIT_PARAMS_SIZE;
    use crate::resource::tests::random_resource;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let input_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let output_resources = [(); NUM_RESOURCE].map(|_| random_resource(&mut rng));
        let a = pallas::Base::random(&mut rng);
        let b = pallas::Base::random(&mut rng);
        let self_resource_id = pallas::Base::random(&mut rng);
        FieldAdditionResourceLogicCircuit {
            self_resource_id,
            input_resources,
            output_resources,
            a,
            b,
        }
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
