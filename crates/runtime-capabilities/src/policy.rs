use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::ModuleId;

/// The close behavior that orchestration must apply when disabling a module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisablePolicy {
    Immediate,
    FinishExecutingRequests,
    DrainStoredTransactions { max_duration: Duration },
    NotRuntimeDisableable,
}

/// One caller-supplied entry in the concrete runtime-module catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleSpec {
    pub id: ModuleId,
    pub dependencies: BTreeSet<ModuleId>,
    pub disable_policy: DisablePolicy,
}

/// Structural defects in a caller-supplied module catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ModuleCatalogError {
    #[error("module {0:?} depends on itself")]
    SelfDependency(ModuleId),
    #[error("module dependency graph contains a cycle through {0:?}")]
    DependencyCycle(ModuleId),
}

/// Checks caller-supplied dependencies within the complete, fixed catalog.
pub(crate) fn validate_dependencies(
    specs: &BTreeMap<ModuleId, ModuleSpec>,
) -> Result<(), ModuleCatalogError> {
    for spec in specs.values() {
        if spec.dependencies.contains(&spec.id) {
            return Err(ModuleCatalogError::SelfDependency(spec.id));
        }
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in ModuleId::ALL {
        visit(id, specs, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit(
    id: ModuleId,
    specs: &BTreeMap<ModuleId, ModuleSpec>,
    visiting: &mut BTreeSet<ModuleId>,
    visited: &mut BTreeSet<ModuleId>,
) -> Result<(), ModuleCatalogError> {
    if visited.contains(&id) {
        return Ok(());
    }
    if !visiting.insert(id) {
        return Err(ModuleCatalogError::DependencyCycle(id));
    }

    let spec = &specs[&id];
    for dependency in &spec.dependencies {
        visit(*dependency, specs, visiting, visited)?;
    }

    visiting.remove(&id);
    visited.insert(id);
    Ok(())
}
