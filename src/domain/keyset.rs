//! JWT 签名密钥材料。
//! active 签名后端用于签发，active 与未退役 previous 公钥用于 JWKS 输出和验签。

use serde_json::Value;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub(crate) struct VerificationKey {
    pub(crate) kid: String,
    pub(crate) public_jwk: Value,
}

#[derive(Clone)]
pub(crate) struct ExternalSigningKey {
    pub(crate) command: Arc<Vec<String>>,
    pub(crate) key_ref: String,
    pub(crate) timeout: Duration,
}

#[derive(Clone)]
pub(crate) enum ActiveSigningKey {
    LocalPkcs8Der(Vec<u8>),
    ExternalCommand(ExternalSigningKey),
}

/// 当前服务实例可用的 JWT keyset。
#[derive(Clone)]
pub(crate) struct Keyset {
    pub(crate) active_kid: String,
    pub(crate) active_alg: jsonwebtoken::Algorithm,
    pub(crate) active_signing_key: ActiveSigningKey,
    pub(crate) verification_keys: Vec<VerificationKey>,
}
