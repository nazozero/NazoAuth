//! Infrastructure-free runtime-module state model.

mod catalog;
mod lease;
mod management;
mod model;
mod policy;
mod reconcile;
mod registry;
mod repository;
mod snapshot;
mod transition;

pub use catalog::{CatalogDurations, ModuleCatalog};
pub use lease::{RequestLease, RequestLeaseTracker, RequestSnapshot};
pub use management::{
    DesiredStateUpdate, DesiredStateUpdateOutcome, RuntimeModuleManagement,
    RuntimeModuleManagementError, RuntimeModuleView,
};
pub use model::{DesiredMode, HistoricalDesiredMode, ModuleEventType, ModuleId, ModuleState};
pub use policy::{DisablePolicy, ModuleCatalogError, ModuleSpec};
pub use reconcile::{
    LifecycleFailure, LifecycleFuture, ModuleLifecycle, NoopModuleLifecycle, ReconcileOutcome,
    RegistryError,
};
pub use registry::RuntimeModuleRegistry;
pub use repository::{
    CasOutcome, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord, InstanceStateChange,
    InstanceStateMutation, InstanceStateObservation, InstanceStateRecord, ModuleEventPage,
    ModuleEventRecord, ModuleEventState, ModuleReconcileState, ModuleStateRepository,
};
pub use snapshot::{ActiveModuleSnapshot, CapabilityAdmission, SnapshotStore};
pub use transition::{ModuleRevision, StaleTransition, TransitionGuard};
