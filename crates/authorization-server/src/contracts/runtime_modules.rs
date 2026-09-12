use std::{future::Future, pin::Pin};

use nazo_runtime_modules::{
    DesiredStateUpdate, DesiredStateUpdateOutcome, ModuleEventPage, RuntimeModuleView,
};

pub type RuntimeModuleAdminFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RuntimeModuleAdminError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeModuleAdminError {
    Unavailable,
    PolicyConflict,
    CatalogInconsistent,
}

/// Infrastructure-neutral administration port used by the Actix adapter.
pub trait RuntimeModuleAdministration: Send + Sync {
    fn list(&self) -> RuntimeModuleAdminFuture<'_, Vec<RuntimeModuleView>>;

    fn events(&self, offset: i64, limit: i64) -> RuntimeModuleAdminFuture<'_, ModuleEventPage>;

    fn update_desired(
        &self,
        update: DesiredStateUpdate,
    ) -> RuntimeModuleAdminFuture<'_, DesiredStateUpdateOutcome>;
}
