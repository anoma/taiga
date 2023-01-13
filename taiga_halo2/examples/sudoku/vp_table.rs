use taiga_halo2::{
    vp_description::ValidityPredicateDescription,
    circuit::vp_circuit::{ValidityPredicateCircuit, ValidityPredicateConfig}
};
use halo2_proofs::circuit::floor_planner::V1;
use std::collections::HashMap;

pub type VPTable = HashMap<ValidityPredicateDescription, Box<dyn ValidityPredicateCircuit<VPConfig = Box<dyn ValidityPredicateConfig>, Config = Box<dyn Clone>, FloorPlanner = V1>>>;