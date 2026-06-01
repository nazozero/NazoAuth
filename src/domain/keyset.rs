//! JWT 签名密钥材料。
//! active 私钥用于签发，active 与未退役 previous 公钥用于 JWKS 输出和验签。

use serde_json::Value;

#[derive(Clone)]
pub(crate) struct VerificationKey {
    pub(crate) kid: String,
    pub(crate) alg: jsonwebtoken::Algorithm,
    pub(crate) public_jwk: Value,
}

/// 当前服务实例可用的 JWT keyset。
#[derive(Clone)]
pub(crate) struct Keyset {
    pub(crate) active_kid: String,
    pub(crate) active_alg: jsonwebtoken::Algorithm,
    pub(crate) active_private_pkcs8_der: Vec<u8>,
    pub(crate) verification_keys: Vec<VerificationKey>,
}
