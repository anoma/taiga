use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    circuit::{floor_planner, AssignedCell, Layouter, Region, Value},
    plonk::{
        keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Constraints, Error,
        Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use rand::RngCore;
use taiga_halo2::{
    circuit::{
        gadgets::{
            assign_free_advice,
            poseidon_hash::poseidon_hash_gadget,
            target_resource_variable::{
                get_is_input_resource_flag, get_owned_resource_variable, GetIsInputResourceFlagConfig,
                GetOwnedResourceVariableConfig,
            },
        },
        resource_circuit::ResourceConfig,
        vp_circuit::{
            BasicValidityPredicateVariables, OutputResourceVariables, VPVerifyingInfo,
            ValidityPredicateCircuit, ValidityPredicateConfig, ValidityPredicateInfo,
            ValidityPredicatePublicInputs, ValidityPredicateVerifyingInfo,
        },
    },
    constant::{NUM_RESOURCE, SETUP_PARAMS_MAP},
    resource::{Resource, RandomSeed},
    proof::Proof,
    utils::poseidon_hash,
    vp_circuit_impl,
    vp_vk::ValidityPredicateVerifyingKey,
};

#[derive(Clone, Debug, Default)]
struct DealerIntentValidityPredicateCircuit {
    owned_resource_id: pallas::Base,
    input_resources: [Resource; NUM_RESOURCE],
    output_resources: [Resource; NUM_RESOURCE],
    encoded_puzzle: pallas::Base,
    sudoku_app_vk: pallas::Base,
    // When it's an output resource, we don't need a valid solution.
    encoded_solution: pallas::Base,
}

#[derive(Clone, Debug)]
struct IntentAppValidityPredicateConfig {
    resource_config: ResourceConfig,
    advices: [Column<Advice>; 10],
    get_owned_resource_variable_config: GetOwnedResourceVariableConfig,
    get_is_input_resource_flag_config: GetIsInputResourceFlagConfig,
    dealer_intent_check_config: DealerIntentCheckConfig,
}

impl ValidityPredicateConfig for IntentAppValidityPredicateConfig {
    fn get_resource_config(&self) -> ResourceConfig {
        self.resource_config.clone()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        let resource_config = Self::configure_resource(meta);

        let advices = resource_config.advices;
        let get_owned_resource_variable_config = GetOwnedResourceVariableConfig::configure(
            meta,
            advices[0],
            [advices[1], advices[2], advices[3], advices[4]],
        );
        let dealer_intent_check_config = DealerIntentCheckConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
        );
        let get_is_input_resource_flag_config =
            GetIsInputResourceFlagConfig::configure(meta, advices[0], advices[1], advices[2]);

        Self {
            resource_config,
            advices,
            get_owned_resource_variable_config,
            get_is_input_resource_flag_config,
            dealer_intent_check_config,
        }
    }
}

impl DealerIntentValidityPredicateCircuit {
    #![allow(dead_code)]
    pub fn compute_app_data_static(
        encoded_puzzle: pallas::Base,
        sudoku_app_vk: pallas::Base,
    ) -> pallas::Base {
        poseidon_hash(encoded_puzzle, sudoku_app_vk)
    }

    fn dealer_intent_check(
        &self,
        config: &IntentAppValidityPredicateConfig,
        mut layouter: impl Layouter<pallas::Base>,
        is_input_resource: &AssignedCell<pallas::Base, pallas::Base>,
        encoded_puzzle: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk_in_dealer_intent_resource: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_resource: &OutputResourceVariables,
    ) -> Result<(), Error> {
        // puzzle_resource_app_data_static = poseidon_hash(encoded_puzzle || encoded_solution)
        let encoded_solution = assign_free_advice(
            layouter.namespace(|| "witness encoded_solution"),
            config.advices[0],
            Value::known(self.encoded_solution),
        )?;
        let puzzle_resource_app_data_static = poseidon_hash_gadget(
            config.get_resource_config().poseidon_config,
            layouter.namespace(|| "app_data_static encoding"),
            [encoded_puzzle.clone(), encoded_solution],
        )?;

        layouter.assign_region(
            || "dealer intent check",
            |mut region| {
                config.dealer_intent_check_config.assign_region(
                    is_input_resource,
                    &puzzle_resource.resource_variables.value,
                    &puzzle_resource.resource_variables.app_vk,
                    sudoku_app_vk_in_dealer_intent_resource,
                    &puzzle_resource.resource_variables.app_data_static,
                    &puzzle_resource_app_data_static,
                    0,
                    &mut region,
                )
            },
        )?;
        Ok(())
    }
}

impl ValidityPredicateInfo for DealerIntentValidityPredicateCircuit {
    fn get_input_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.input_resources
    }

    fn get_output_resources(&self) -> &[Resource; NUM_RESOURCE] {
        &self.output_resources
    }

    fn get_public_inputs(&self, mut rng: impl RngCore) -> ValidityPredicatePublicInputs {
        let mut public_inputs = self.get_mandatory_public_inputs();
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

impl ValidityPredicateCircuit for DealerIntentValidityPredicateCircuit {
    type VPConfig = IntentAppValidityPredicateConfig;
    // Add custom constraints
    fn custom_constraints(
        &self,
        config: Self::VPConfig,
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

        // search target resource and output the app_static_data
        let app_data_static = get_owned_resource_variable(
            config.get_owned_resource_variable_config,
            layouter.namespace(|| "get owned resource app_static_data"),
            &owned_resource_id,
            &basic_variables.get_app_data_static_searchable_pairs(),
        )?;

        // app_data_static = poseidon_hash(encoded_puzzle || sudoku_app_vk)
        let encoded_puzzle = assign_free_advice(
            layouter.namespace(|| "witness encoded_puzzle"),
            config.advices[0],
            Value::known(self.encoded_puzzle),
        )?;
        let sudoku_app_vk = assign_free_advice(
            layouter.namespace(|| "witness sudoku_app_vk"),
            config.advices[0],
            Value::known(self.sudoku_app_vk),
        )?;
        let app_data_static_encode = poseidon_hash_gadget(
            config.get_resource_config().poseidon_config,
            layouter.namespace(|| "app_data_static encoding"),
            [encoded_puzzle.clone(), sudoku_app_vk.clone()],
        )?;

        layouter.assign_region(
            || "check app_data_static encoding",
            |mut region| {
                region.constrain_equal(app_data_static_encode.cell(), app_data_static.cell())
            },
        )?;

        // if it is an output resource, do nothing
        // if it is an input resource, 1. check the zero value of puzzle_resource; 2. check the puzzle equality.
        self.dealer_intent_check(
            &config,
            layouter.namespace(|| "dealer intent check"),
            &is_input_resource,
            &encoded_puzzle,
            &sudoku_app_vk,
            &basic_variables.output_resource_variables[0],
        )
    }
}

vp_circuit_impl!(DealerIntentValidityPredicateCircuit);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealerIntentCheckConfig {
    q_dealer_intent_check: Selector,
    is_input_resource: Column<Advice>,
    puzzle_resource_value: Column<Advice>,
    sudoku_app_vk: Column<Advice>,
    sudoku_app_vk_in_dealer_intent_resource: Column<Advice>,
    puzzle_resource_app_data_static: Column<Advice>,
    puzzle_resource_app_data_static: Column<Advice>,
}

impl DealerIntentCheckConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        is_input_resource: Column<Advice>,
        puzzle_resource_value: Column<Advice>,
        sudoku_app_vk: Column<Advice>,
        sudoku_app_vk_in_dealer_intent_resource: Column<Advice>,
        puzzle_resource_app_data_static: Column<Advice>,
        puzzle_resource_app_data_static: Column<Advice>,
    ) -> Self {
        meta.enable_equality(is_input_resource);
        meta.enable_equality(puzzle_resource_value);
        meta.enable_equality(sudoku_app_vk);
        meta.enable_equality(sudoku_app_vk_in_dealer_intent_resource);
        meta.enable_equality(puzzle_resource_app_data_static);
        meta.enable_equality(puzzle_resource_app_data_static);

        let config = Self {
            q_dealer_intent_check: meta.selector(),
            is_input_resource,
            puzzle_resource_value,
            sudoku_app_vk,
            sudoku_app_vk_in_dealer_intent_resource,
            puzzle_resource_app_data_static,
            puzzle_resource_app_data_static,
        };

        config.create_gate(meta);

        config
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<pallas::Base>) {
        meta.create_gate("check dealer intent", |meta| {
            let q_dealer_intent_check = meta.query_selector(self.q_dealer_intent_check);
            let is_input_resource = meta.query_advice(self.is_input_resource, Rotation::cur());
            let puzzle_resource_value = meta.query_advice(self.puzzle_resource_value, Rotation::cur());
            let sudoku_app_vk = meta.query_advice(self.sudoku_app_vk, Rotation::cur());
            let sudoku_app_vk_in_dealer_intent_resource =
                meta.query_advice(self.sudoku_app_vk_in_dealer_intent_resource, Rotation::cur());
            let puzzle_resource_app_data_static =
                meta.query_advice(self.puzzle_resource_app_data_static, Rotation::cur());
            let puzzle_resource_app_data_static =
                meta.query_advice(self.puzzle_resource_app_data_static, Rotation::cur());

            let bool_check_is_input = bool_check(is_input_resource.clone());

            Constraints::with_selector(
                q_dealer_intent_check,
                [
                    ("bool_check_is_input", bool_check_is_input),
                    (
                        "check zero value of puzzle resource",
                        is_input_resource.clone() * puzzle_resource_value,
                    ),
                    (
                        "check sudoku_app_vk",
                        is_input_resource.clone()
                            * (sudoku_app_vk - sudoku_app_vk_in_dealer_intent_resource),
                    ),
                    (
                        "check puzzle resource app_data_static encoding",
                        is_input_resource
                            * (puzzle_resource_app_data_static - puzzle_resource_app_data_static),
                    ),
                ],
            )
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_region(
        &self,
        is_input_resource: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_resource_value: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk: &AssignedCell<pallas::Base, pallas::Base>,
        sudoku_app_vk_in_dealer_intent_resource: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_resource_app_data_static: &AssignedCell<pallas::Base, pallas::Base>,
        puzzle_resource_app_data_static: &AssignedCell<pallas::Base, pallas::Base>,
        offset: usize,
        region: &mut Region<'_, pallas::Base>,
    ) -> Result<(), Error> {
        // Enable `q_dealer_intent_check` selector
        self.q_dealer_intent_check.enable(region, offset)?;

        is_input_resource.copy_advice(|| "is_input_resource", region, self.is_input_resource, offset)?;
        puzzle_resource_value.copy_advice(
            || "puzzle_resource_value",
            region,
            self.puzzle_resource_value,
            offset,
        )?;
        sudoku_app_vk.copy_advice(|| "sudoku_app_vk", region, self.sudoku_app_vk, offset)?;
        sudoku_app_vk_in_dealer_intent_resource.copy_advice(
            || "sudoku_app_vk_in_dealer_intent_resource",
            region,
            self.sudoku_app_vk_in_dealer_intent_resource,
            offset,
        )?;
        puzzle_resource_app_data_static.copy_advice(
            || "puzzle_resource_app_data_static",
            region,
            self.puzzle_resource_app_data_static,
            offset,
        )?;
        puzzle_resource_app_data_static.copy_advice(
            || "puzzle_resource_app_data_static",
            region,
            self.puzzle_resource_app_data_static,
            offset,
        )?;

        Ok(())
    }
}

#[test]
fn test_halo2_dealer_intent_vp_circuit() {
    use crate::app_vp::tests::{random_input_resource, random_output_resource};
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let circuit = {
        let input_resources = [(); NUM_RESOURCE].map(|_| random_input_resource(&mut rng));
        let mut output_resources = input_resources
            .iter()
            .map(|input| random_output_resource(&mut rng, input.get_nf().unwrap()))
            .collect::<Vec<_>>();
        let encoded_puzzle = pallas::Base::random(&mut rng);
        let sudoku_app_vk = pallas::Base::random(&mut rng);
        output_resources[0].kind.app_data_static =
            DealerIntentValidityPredicateCircuit::compute_app_data_static(
                encoded_puzzle,
                sudoku_app_vk,
            );
        let encoded_solution = pallas::Base::random(&mut rng);
        let owned_resource_id = output_resources[0].commitment().inner();
        DealerIntentValidityPredicateCircuit {
            owned_resource_id,
            input_resources,
            output_resources: output_resources.try_into().unwrap(),
            encoded_puzzle,
            sudoku_app_vk,
            encoded_solution,
        }
    };
    let public_inputs = circuit.get_public_inputs(&mut rng);

    let prover =
        MockProver::<pallas::Base>::run(12, &circuit, vec![public_inputs.to_vec().clone()])
            .unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let params = SETUP_PARAMS_MAP.get(&12).unwrap();
    let vk = keygen_vk(params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(params, vk.clone(), &circuit).expect("keygen_pk should not fail");
    let proof = Proof::create(&pk, params, circuit, &[public_inputs.inner()], &mut rng).unwrap();

    proof.verify(&vk, params, &[public_inputs.inner()]).unwrap();
}
