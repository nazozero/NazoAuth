#![forbid(unsafe_code)]
//! Cloudflare Workers composition of the portable NazoAuth application.

mod composition;
mod config;
mod outbound;
#[cfg(all(feature = "provisioning", not(target_arch = "wasm32")))]
pub mod provisioning;
mod services;

pub use composition::WorkerApplication;
pub use config::{Ingress, WorkerConfiguration, WorkerSecrets, WorkerServices};

#[cfg(target_arch = "wasm32")]
mod host;
#[cfg(target_arch = "wasm32")]
mod mtls;
#[cfg(target_arch = "wasm32")]
mod setup;
#[cfg(target_arch = "wasm32")]
mod ui;
