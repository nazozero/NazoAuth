//! 跨 HTTP handler 复用的领域支撑模块。
// 子模块按职责拆分；调用方显式导入所需能力。
mod audit;
mod avatars;
mod client_ip;
mod cookies;
mod dpop;
mod email;
mod email_templates;
mod fapi_http_signatures;
mod jwe;
mod mfa;
mod mtls;
mod oauth;
mod oidc_claims;
mod passkeys;
mod rate_limit;
mod responses;
mod sector_identifier;
mod security;
mod sessions;
mod tenancy;
#[cfg(test)]
mod valkey;
mod views;

#[cfg(test)]
pub(crate) use crate::test_support::{ClientSigningFixture, client_signing_fixture};
pub(crate) use audit::*;
pub(crate) use avatars::*;
pub(crate) use client_ip::*;
pub(crate) use cookies::*;
pub(crate) use dpop::*;
pub(crate) use email::*;
pub(crate) use fapi_http_signatures::*;
pub(crate) use jwe::*;
pub(crate) use mfa::*;
pub(crate) use mtls::*;
pub(crate) use nazo_key_management::{signing_algorithm_from_name, signing_algorithm_name};
pub(crate) use oauth::*;
pub(crate) use oidc_claims::*;
pub(crate) use passkeys::*;
pub(crate) use rate_limit::*;
pub(crate) use responses::*;
pub(crate) use sector_identifier::*;
pub(crate) use security::*;
pub(crate) use sessions::*;
pub(crate) use tenancy::*;
#[cfg(test)]
pub(crate) use valkey::*;
pub(crate) use views::*;
