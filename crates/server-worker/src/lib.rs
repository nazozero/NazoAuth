#![forbid(unsafe_code)]
//! Cloudflare Workers composition of the portable NazoAuth application.

mod composition;
mod config;
#[cfg(all(feature = "provisioning", not(target_arch = "wasm32")))]
pub mod provisioning;
mod services;

pub use composition::WorkerApplication;
pub use config::{Ingress, WorkerConfiguration};

#[cfg(target_arch = "wasm32")]
mod host;
