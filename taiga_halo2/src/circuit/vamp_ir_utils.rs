/// This module consists of definitions that will eventually be incorporated into the vamp-ir library
use pasta_curves::Fp;
use std::collections::HashMap;
use vamp_ir::ast::{Module, Pat, VariableId};

use vamp_ir::transform::collect_module_variables;

#[derive(Debug)]
pub(crate) enum VariableAssignmentError {
    MissingAssignment(String),
}

/// Convert named circuit assignments to assignments of vamp-ir variableIds.
/// Useful for calling vamp-ir Halo2Module::populate_variable_assignments
pub(crate) fn get_circuit_assignments(
    module: &Module,
    named_assignments: &HashMap<String, Fp>,
) -> Result<HashMap<VariableId, Fp>, VariableAssignmentError> {
    let mut input_variables = HashMap::new();
    collect_module_variables(module, &mut input_variables);
    // Defined variables should not be requested from user
    for def in &module.defs {
        if let Pat::Variable(var) = &def.0 .0.v {
            input_variables.remove(&var.id);
        }
    }

    input_variables
        .iter()
        .filter_map(|(id, expected_var)| {
            expected_var.name.as_deref().map(|var_name| {
                named_assignments
                    .get(var_name)
                    .cloned()
                    .ok_or_else(|| VariableAssignmentError::MissingAssignment(var_name.to_string()))
                    .map(|assignment| (*id, assignment))
            })
        })
        .collect()
}

pub(crate) fn parse(unparsed_file: &str) -> Result<Module, String> {
    Module::parse(unparsed_file).map_err(|err| err.to_string())
}
