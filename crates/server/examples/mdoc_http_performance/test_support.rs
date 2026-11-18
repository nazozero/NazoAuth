//! Reuse the regression fixtures without importing their endpoint test modules.
#[path = "../../tests/support/infrastructure.rs"]
mod infrastructure;
pub(crate) use infrastructure::{
    TestInfrastructure, initialize_audit_dependencies, persisted_runtime_modules_fixture,
};

#[path = "../../tests/support/facade.rs"]
pub(crate) mod facade;
