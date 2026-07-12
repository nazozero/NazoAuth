//! Infrastructure-free runtime-module state model.

mod model;
mod policy;
mod repository;
mod snapshot;
mod transition;

pub use model::{DesiredMode, ModuleEventType, ModuleId, ModuleState};
pub use policy::{DisablePolicy, ModuleCatalogError, ModuleSpec, validate_module_specs};
pub use repository::{
    CasOutcome, DesiredStateChange, DesiredStateRecord, InstanceStateChange, InstanceStateRecord,
    ModuleEventRecord, ModuleEventState, ModuleStateRepository,
};
pub use snapshot::{ActiveModuleSnapshot, SnapshotStore};
pub use transition::{ModuleRevision, StaleTransition, TransitionGuard};
