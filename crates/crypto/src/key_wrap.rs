//! RSA key transport (fixed JWA RSA-OAEP-256) and RFC 3394 AES key wrap.

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    path = "key_wrap/portable.rs"
)]
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    path = "key_wrap/native.rs"
)]
mod backend;

pub use backend::{
    RsaOaep256PrivateKey, aes_wrap, generate_rsa_pkcs8_der, rsa_oaep256_encrypt,
    rsa_oaep256_keypair, rsa_public_components,
};

pub type RsaPublicComponents = (Vec<u8>, Vec<u8>, Vec<u8>);
