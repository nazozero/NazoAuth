use std::sync::{Arc, OnceLock};

use crate::{CryptoError, jwt::Algorithm};
use futures_channel::oneshot;
use js_sys::{
    Promise, Uint8Array,
    futures::{JsFuture, spawn_local},
};
use pkcs8::{
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfoRef, SecretDocument,
    der::asn1::{AnyRef, OctetStringRef},
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = "
export async function importRsaKey(der, pss) {
    const name = pss ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5';
    return globalThis.crypto.subtle.importKey('pkcs8', der, {name, hash: 'SHA-256'}, false, ['sign']);
}
export async function signRsa(key, input, pss) {
    const algorithm = pss ? {name: 'RSA-PSS', saltLength: 32} : 'RSASSA-PKCS1-v1_5';
    return new Uint8Array(await globalThis.crypto.subtle.sign(algorithm, key, input));
}
")]
extern "C" {
    #[wasm_bindgen(js_name = importRsaKey)]
    fn import_rsa_key(der: &[u8], pss: bool) -> Promise;
    #[wasm_bindgen(js_name = signRsa)]
    fn sign_rsa(key: &JsValue, input: &[u8], pss: bool) -> Promise;
}

/// The validated key material owns the imported, non-extractable CryptoKey.
pub(crate) struct WorkerRsa {
    pss: bool,
    pkcs8: SecretDocument,
    key: OnceLock<JsValue>,
}

impl WorkerRsa {
    pub(crate) fn new(algorithm: Algorithm, pkcs1: &[u8]) -> crate::Result<Option<Self>> {
        let pss = match algorithm {
            Algorithm::RS256 => false,
            Algorithm::PS256 => true,
            _ => return Ok(None),
        };
        // RSA signing keys are persisted in PKCS#1. Wrap the already
        // validated bytes in the PKCS#8 container expected by WebCrypto.
        let algorithm = AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
            parameters: Some(AnyRef::NULL),
        };
        let pkcs1 = OctetStringRef::new(pkcs1).map_err(|_| CryptoError::InvalidKey)?;
        let pkcs8 = SecretDocument::encode_msg(&PrivateKeyInfoRef::new(algorithm, pkcs1))
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Some(Self {
            pss,
            pkcs8,
            key: OnceLock::new(),
        }))
    }

    pub(crate) async fn sign(self: &Arc<Self>, input: &[u8]) -> crate::Result<Vec<u8>> {
        let import = self
            .key
            .get()
            .is_none()
            .then(|| import_rsa_key(self.pkcs8.as_bytes(), self.pss));

        let input = input.to_vec();
        let signing = Arc::clone(self);
        let (sender, receiver) = oneshot::channel();
        // Promise futures are isolate-local. Only the result crosses back into
        // the Send future, and concurrent requests share only a completed key.
        spawn_local(async move {
            let result = async {
                if let Some(promise) = import {
                    let imported = JsFuture::from(promise)
                        .await
                        .map_err(|_| CryptoError::OperationFailed)?;
                    let _ = signing.key.set(imported);
                }
                let key = signing.key.get().ok_or(CryptoError::InvalidKey)?;
                let signature = JsFuture::from(sign_rsa(key, &input, signing.pss))
                    .await
                    .map_err(|_| CryptoError::OperationFailed)?;
                Ok(Uint8Array::from(signature).to_vec())
            }
            .await;
            let _ = sender.send(result);
        });
        receiver.await.map_err(|_| CryptoError::OperationFailed)?
    }
}
