//! ISO/IEC 18013-5 mobile document (mdoc) library.
//!
//! Provides parsing, verification, selective disclosure, device authentication,
//! and document issuance for mdoc credentials (mDL, EUDIW PID).
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`cbor`] | CBOR utilities (Tag 24, Tag 1004) |
//! | [`cose`] | COSE key conversion |
//! | [`model`] | ISO 18013-5 data model |
//! | [`parser`] | CBOR bytes → MDoc |
//! | [`verifier`] | Full verification pipeline |
//! | [`disclosure`] | Selective disclosure digest verification |
//! | [`device_auth`] | Device authentication (Sign1 + Mac0) |
//! | [`session`] | Session transcript construction |
//!
//! Feature-gated modules:
//!
//! | Module | Feature | Purpose |
//! |--------|---------|---------|
//! | [`builder`] | `issue` | Document building/signing |
//! | [`response_builder`] | `issue` | DeviceResponse builder |
//! | [`encoder`] | `issue` | DeviceResponse/Document CBOR encoder |
//! | [`diagnostic`] | `debug` | CBOR diagnostic-notation pretty printer |

pub mod cbor;
pub mod cose;
pub mod error;
pub mod model;

pub mod device_auth;
pub mod disclosure;
pub mod parser;
pub mod session;
pub mod verifier;

#[cfg(feature = "issue")]
pub mod builder;
#[cfg(feature = "debug")]
pub mod diagnostic;
#[cfg(feature = "issue")]
pub mod encoder;
#[cfg(feature = "issue")]
pub mod response_builder;

pub use error::MdocError;
pub use model::{MDoc, MDocStatus};
pub use parser::{parse, parse_hex};
pub use verifier::{Verifier, VerifyOptions};
