//! Ed25519 JWT 签名密钥材料。
//! active 私钥用于签发，active 与未退役 previous 公钥用于 JWKS 输出和验签。

#[derive(Clone)]
pub(crate) struct VerificationKey {
    pub(crate) kid: String,
    pub(crate) public_key: [u8; 32],
}

/// 当前服务实例可用的 JWT keyset。
#[derive(Clone)]
pub(crate) struct Keyset {
    pub(crate) active_kid: String,
    pub(crate) active_private_pkcs8_der: Vec<u8>,
    pub(crate) verification_keys: Vec<VerificationKey>,
}
