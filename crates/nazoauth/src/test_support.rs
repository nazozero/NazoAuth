//! Test-only visibility. All exported items are the production implementation;
//! no endpoint graph, request policy, or handler is duplicated here.

pub mod endpoints {
    pub use crate::endpoints::*;
}
pub mod http {
    pub use crate::http::*;
}
pub mod runtime_modules {
    pub use crate::runtime_modules::*;
}
pub mod well_known {
    pub use crate::well_known::*;
}

pub mod control_discovery {
    pub use crate::control_discovery::*;
}

pub use crate::composition::DummyPasswordHash;
pub use crate::composition::audit::{
    TracingAuthenticationAudit, TracingFederationAudit, TracingPasskeyAudit,
};

pub mod openid4vc {
    pub use crate::openid4vc::*;
}

pub mod control {
    pub use crate::control::*;
}

pub use crate::routes::{RouteMatch, resolve};
