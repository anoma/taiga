/// This module consists of definitions that will eventually be incorporated into the vamp-ir library
use pasta_curves::Fp;
use std::collections::HashMap;
use vamp_ir::ast::{Module, Pat, VariableId};

use vamp_ir::transform::collect_module_variables;

/// Convert named circuit assignments to assignments of vamp-ir variableIds.
/// Useful for calling vamp-ir Halo2Module::populate_variable_assignments
pub fn get_circuit_assignments(
    module: &Module,
    named_assignments: &HashMap<String, Fp>,
) -> HashMap<VariableId, Fp> {
    let mut input_variables = HashMap::new();
    collect_module_variables(module, &mut input_variables);
    // Defined variables should not be requested from user
    for def in &module.defs {
        if let Pat::Variable(var) = &def.0 .0.v {
            input_variables.remove(&var.id);
        }
    }

    let variable_assignments = input_variables
        .iter()
        .filter_map(|(id, expected_var)| {
            expected_var.name.as_deref().map(|var_name| {
                let assignment = *named_assignments.get(var_name).unwrap_or_else(|| {
                    panic!("missing assignment for variable with name {}", var_name)
                });
                (*id, assignment)
            })
        })
        .collect();
    variable_assignments
}
