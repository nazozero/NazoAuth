use std::sync::{Arc, OnceLock};

use crate::{CryptoError, jwt::Algorithm};
use futures_channel::oneshot;
use js_sys::{
    Array, Promise, Uint8Array,
    futures::{JsFuture, spawn_local},
};
use pkcs8::{
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfoRef, SecretDocument,
    der::asn1::{AnyRef, OctetStringRef},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = "
export async function importSigningKey(der, name) {
    const algorithm = name === 'ECDSA' ? {name, namedCurve: 'P-256'}
        : name === 'Ed25519' ? name : {name, hash: 'SHA-256'};
    return globalThis.crypto.subtle.importKey('pkcs8', der, algorithm, false, ['sign']);
}
export async function signWithKey(key, importing, input, name) {
    if (!key) {
        // The borrowed WASM view must not survive the import's await.
        input = input.slice();
        key = await importing;
    }
    const algorithm = name === 'RSA-PSS' ? {name, saltLength: 32}
        : name === 'ECDSA' ? {name, hash: 'SHA-256'} : name;
    // WebCrypto snapshots BufferSource before returning its promise. A warm
    // key signs the borrowed WASM view directly, without an intermediate copy.
    const signature = await globalThis.crypto.subtle.sign(algorithm, key, input);
    return [key, new Uint8Array(signature)];
}
")]
extern "C" {
    #[wasm_bindgen(js_name = importSigningKey)]
    fn import_signing_key(der: &[u8], name: &str) -> Promise;
    #[wasm_bindgen(js_name = signWithKey)]
    fn sign_with_key(key: &JsValue, importing: &JsValue, input: &[u8], name: &str) -> Promise;
}

/// The validated key material owns the imported, non-extractable CryptoKey.
pub(crate) struct WorkerSigningKey {
    name: &'static str,
    pkcs8: SecretDocument,
    key: OnceLock<JsValue>,
}

impl WorkerSigningKey {
    pub(crate) fn new(algorithm: Algorithm, private_der: &[u8]) -> crate::Result<Self> {
        let name = match algorithm {
            Algorithm::RS256 => "RSASSA-PKCS1-v1_5",
            Algorithm::PS256 => "RSA-PSS",
            Algorithm::ES256 => "ECDSA",
            Algorithm::EdDSA => "Ed25519",
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        };
        let pkcs8 = if matches!(algorithm, Algorithm::RS256 | Algorithm::PS256) {
            // RSA signing keys are persisted in PKCS#1. Wrap the already
            // validated bytes in the PKCS#8 container expected by WebCrypto.
            let algorithm = AlgorithmIdentifierRef {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                parameters: Some(AnyRef::NULL),
            };
            let pkcs1 = OctetStringRef::new(private_der).map_err(|_| CryptoError::InvalidKey)?;
            SecretDocument::encode_msg(&PrivateKeyInfoRef::new(algorithm, pkcs1))
        } else {
            // RustCrypto already validated the key and its optional public
            // component. WebCrypto accepts PKCS#8 v1, so omit the outer v2
            // public-key field while preserving the private-key encoding.
            let private =
                PrivateKeyInfoRef::try_from(private_der).map_err(|_| CryptoError::InvalidKey)?;
            SecretDocument::encode_msg(&PrivateKeyInfoRef::new(
                private.algorithm,
                private.private_key,
            ))
        };
        Ok(Self {
            name,
            pkcs8: pkcs8.map_err(|_| CryptoError::InvalidKey)?,
            key: OnceLock::new(),
        })
    }

    pub(crate) async fn sign(self: &Arc<Self>, input: &[u8]) -> crate::Result<Vec<u8>> {
        let key = self.key.get();
        let import = key
            .is_none()
            .then(|| import_signing_key(self.pkcs8.as_bytes(), self.name));
        let promise = sign_with_key(
            key.unwrap_or(&JsValue::UNDEFINED),
            import.as_ref().map_or(&JsValue::UNDEFINED, AsRef::as_ref),
            input,
            self.name,
        );
        let signing = Arc::clone(self);
        let (sender, receiver) = oneshot::channel();
        // Promise futures are isolate-local. Only the result crosses back into
        // the Send future, and concurrent requests share only a completed key.
        spawn_local(async move {
            let result = async {
                let signed = JsFuture::from(promise)
                    .await
                    .map_err(|_| CryptoError::OperationFailed)?;
                let signed: Array = signed.unchecked_into();
                let _ = signing.key.set(signed.get(0));
                let signature: Uint8Array = signed.get(1).unchecked_into();
                Ok(signature.to_vec())
            }
            .await;
            let _ = sender.send(result);
        });
        receiver.await.map_err(|_| CryptoError::OperationFailed)?
    }
}
