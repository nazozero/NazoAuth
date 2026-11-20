use std::sync::{Arc, OnceLock};

use futures_channel::oneshot;
use js_sys::{
    Promise, Uint8Array,
    futures::{JsFuture, spawn_local},
};
use nazo_auth::SignError;
use nazo_crypto::jwt::Algorithm;
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
    key: OnceLock<JsValue>,
}

impl WorkerRsa {
    pub(crate) fn new(algorithm: Algorithm) -> Option<Self> {
        let pss = match algorithm {
            Algorithm::RS256 => false,
            Algorithm::PS256 => true,
            _ => return None,
        };
        Some(Self {
            pss,
            key: OnceLock::new(),
        })
    }

    pub(crate) async fn sign(
        self: &Arc<Self>,
        pkcs1: &[u8],
        input: &[u8],
    ) -> Result<Vec<u8>, SignError> {
        let import = if self.key.get().is_none() {
            // RSA signing keys are persisted in PKCS#1. Wrap the already
            // validated bytes in the PKCS#8 container expected by WebCrypto.
            let algorithm = AlgorithmIdentifierRef {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                parameters: Some(AnyRef::NULL),
            };
            let pkcs1 = OctetStringRef::new(pkcs1).map_err(|_| SignError::SigningFailed)?;
            let document = SecretDocument::encode_msg(&PrivateKeyInfoRef::new(algorithm, pkcs1))
                .map_err(|_| SignError::SigningFailed)?;
            Some(import_rsa_key(document.as_bytes(), self.pss))
        } else {
            None
        };

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
                        .map_err(|_| SignError::SigningFailed)?;
                    let _ = signing.key.set(imported);
                }
                let key = signing.key.get().ok_or(SignError::KeyUnavailable)?;
                let signature = JsFuture::from(sign_rsa(key, &input, signing.pss))
                    .await
                    .map_err(|_| SignError::SigningFailed)?;
                Ok(Uint8Array::from(signature).to_vec())
            }
            .await;
            let _ = sender.send(result);
        });
        receiver.await.map_err(|_| SignError::SigningFailed)?
    }
}
