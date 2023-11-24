use crate::{
    circuit::{
        blake2s::publicize_default_dynamic_vp_commitments,
        gadgets::{
            add::{AddChip, AddInstructions},
            assign_free_advice,
        },
        vp_circuit::{
            BasicValidityPredicateVariables, VPVerifyingInfo, ValidityPredicateCircuit,
            ValidityPredicateConfig, ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP, VP_CIRCUIT_CUSTOM_PUBLIC_INPUT_BEGIN_IDX},
    error::TransactionError,
    proof::Proof,
    resource::{RandomSeed, Resource},
    vp_commitment::ValidityPredicateCommitment,
    vp_vk::ValidityPredicateVerifyingKey,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;

// FieldAdditionValidityPredicateCircuit with a trivial constraint a + b = c.
#[derive(Clone, Debug, Default)]
struct FieldAdditionValidityPredicateCircuit {
    owned_resource_id: pallas::Base,
    input_resources: [Resource; NUM_RESOURCE],
    output_resources: [Resource; NUM_RESOURCE],
    a: pallas::Base,
    b: pallas::Base,
}

impl ValidityPredicateCircuit for FieldAdditionValidityPredicateCircuit {
    // Add custom constraints
    // Resource: the trivial vp doesn't constrain on input_resource_variables and output_resource_variables
    fn custom_constraints(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
        _basic_variables: BasicValidityPredicateVariables,
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
            VP_CIRCUIT_CUSTOM_PUBLIC_INPUT_BEGIN_IDX,
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
        public_inputs.push(self.a + self.b);
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

vp_circuit_impl!(FieldAdditionValidityPredicateCircuit);
vp_verifying_info_impl!(FieldAdditionValidityPredicateCircuit);

#[test]
fn test_halo2_addition_vp_circuit() {
    use crate::constant::VP_CIRCUIT_PARAMS_SIZE;
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
        let owned_resource_id = pallas::Base::random(&mut rng);
        FieldAdditionValidityPredicateCircuit {
            owned_resource_id,
            input_resources,
            output_resources,
            a,
            b,
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
