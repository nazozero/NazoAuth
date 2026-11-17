//! Standalone native HTTP measurement without the server's unrelated test tree.
// Shared native files contain APIs outside this deliberately narrow workload.
#![allow(dead_code, unused_imports)]
#![forbid(unsafe_code)]

use nazo_server as _;

#[path = "../../src"]
mod native {
    pub(crate) mod adapters;
    pub(crate) mod config;
    pub(crate) mod runtime_modules;
    pub(crate) mod settings;

    #[path = "bootstrap"]
    pub(crate) mod services {
        pub(crate) mod authentication_services;
        pub(crate) mod registration_services;
    }
}
use native::services::{authentication_services, registration_services};
pub(crate) use native::{adapters, config, runtime_modules, settings};

mod bootstrap {
    pub(crate) use crate::authentication_services::LoginPasswordVerifier;
    pub(crate) use crate::registration_services::RegistrationSecretHasher;

    mod assembly {
        pub(crate) mod native {
            include!("native_capabilities.rs");
        }
    }

    pub(crate) mod test_support {
        pub(crate) use super::assembly::native::application_capabilities;
    }
}

mod api;
mod native_crypto;
mod test_support;

#[path = "../../tests/unit/mdoc_http_performance.rs"]
mod measurement;

fn assembly_function(source: &str) -> &str {
    let start = source
        .find("pub(crate) fn application_capabilities(")
        .expect("native capability assembler must exist");
    let function = &source[start..];
    let end = function.find("\n}\n").expect("complete native assembler") + 3;
    &function[..end]
}

fn main() {
    // Only native capability wiring is copied for private-module visibility.
    // A changed production assembler must update this fixture before measuring.
    assert_eq!(
        assembly_function(include_str!("../../src/bootstrap/startup/services.rs")),
        assembly_function(include_str!("native_capabilities.rs")),
        "benchmark capability wiring must match the production assembler exactly"
    );
    actix_web::rt::System::new().block_on(async {
        match std::env::var("NAZO_MDOC_ACTION")
            .as_deref()
            .unwrap_or("http")
        {
            "http" => measurement::run().await,
            "native-api" => api::measure().await,
            "interop-export" => api::export().await,
            "interop-verify" => api::verify_export().await,
            other => panic!("unknown NAZO_MDOC_ACTION: {other}"),
        }
    });
}
