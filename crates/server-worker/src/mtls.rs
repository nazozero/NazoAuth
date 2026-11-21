//! Certificate proof comes only from Cloudflare's request metadata. Caller
//! headers never become TLS facts, including fields named Client-Cert.
use http::{HeaderMap, HeaderValue};
use std::sync::Arc;
use worker::{js_sys::Reflect, wasm_bindgen::JsValue};

pub(crate) struct PresentedCertificate {
    leaf: String,
    chain: String,
    fingerprint: String,
    trusted: bool,
}

impl PresentedCertificate {
    pub(crate) fn capture(request: &worker::Request) -> Option<Self> {
        let cf = Reflect::get(request.inner().as_ref(), &JsValue::from_str("cf")).ok()?;
        let tls = Reflect::get(&cf, &JsValue::from_str("tlsClientAuth")).ok()?;
        if tls.is_null() || tls.is_undefined() {
            return None;
        }
        let text = |name: &str| {
            Reflect::get(&tls, &JsValue::from_str(name))
                .ok()?
                .as_string()
        };
        let flag = |name: &str| Reflect::get(&tls, &JsValue::from_str(name)).ok()?.as_bool();
        if text("certPresented").as_deref() != Some("1")
            || text("certRevoked").as_deref() != Some("0")
            || flag("certRFC9440TooLarge") != Some(false)
            || flag("certChainRFC9440TooLarge") != Some(false)
        {
            return None;
        }
        let leaf = text("certRFC9440")?;
        let chain = text("certChainRFC9440").unwrap_or_default();
        if leaf.len() > 10 * 1024 || chain.len() > 16 * 1024 {
            return None;
        }
        Some(Self {
            leaf,
            chain,
            fingerprint: text("certFingerprintSHA256")?,
            trusted: text("certVerified").as_deref() == Some("SUCCESS"),
        })
    }

    pub(crate) fn facts(self) -> Option<Arc<nazoauth::integration::ClientCertificateFacts>> {
        let mut fields = HeaderMap::new();
        fields.insert("client-cert", HeaderValue::from_str(&self.leaf).ok()?);
        if !self.chain.is_empty() {
            fields.insert(
                "client-cert-chain",
                HeaderValue::from_str(&self.chain).ok()?,
            );
        }
        let mut certificate = nazoauth::integration::client_certificate_from_rfc9440(&fields)?;
        let fingerprint = nazo_auth::normalize_sha256_thumbprint(&self.fingerprint)?;
        if certificate.thumbprint.as_deref() != Some(fingerprint.as_ref()) {
            return None;
        }
        certificate.deployment_trusted_chain = self.trusted;
        Some(Arc::new(certificate))
    }
}
