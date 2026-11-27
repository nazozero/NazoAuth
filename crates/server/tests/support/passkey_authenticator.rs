//! Shared deterministic WebAuthn authenticator for native protocol tests.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use ed25519_dalek::{Signer, SigningKey};
use nazo_passkey::{AuthenticationResponse, RegistrationResponse};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) struct FakeAuthenticator {
    sk: SigningKey,
    credential_id: Vec<u8>,
    pub(crate) counter: u32,
    pub(crate) flags: u8,
}

pub(crate) const FLAG_UP: u8 = 1 << 0;
pub(crate) const FLAG_UV: u8 = 1 << 2;
const FLAG_AT: u8 = 1 << 6;

impl FakeAuthenticator {
    pub(crate) fn new(label: &[u8]) -> Self {
        let digest = Sha256::digest(label);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        Self {
            sk: SigningKey::from_bytes(&seed),
            credential_id: label.to_vec(),
            counter: 0,
            flags: FLAG_UP | FLAG_UV,
        }
    }

    pub(crate) fn registration_response(
        &self,
        challenge_b64: &str,
        origin: &str,
    ) -> RegistrationResponse {
        serde_json::from_value(self.registration_response_json(challenge_b64, origin)).unwrap()
    }

    pub(crate) fn registration_response_json(&self, challenge_b64: &str, origin: &str) -> Value {
        let (_raw, client_data_json) = client_data("webauthn.create", challenge_b64, origin);
        json!({
            "id": B64URL.encode(&self.credential_id),
            "rawId": B64URL.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "transports": ["internal"],
                "attestationObject": B64URL.encode(self.attestation_object()),
                "clientDataJSON": client_data_json,
            },
            "clientExtensionResults": {},
        })
    }

    pub(crate) fn authentication_response(
        &mut self,
        challenge_b64: &str,
        origin: &str,
        user_handle: Option<&[u8]>,
    ) -> AuthenticationResponse {
        serde_json::from_value(self.authentication_response_json(
            challenge_b64,
            origin,
            user_handle,
        ))
        .unwrap()
    }

    pub(crate) fn authentication_response_json(
        &mut self,
        challenge_b64: &str,
        origin: &str,
        user_handle: Option<&[u8]>,
    ) -> Value {
        let auth_data = self.auth_data_authenticate(None);
        let (client_data_raw, client_data_json) =
            client_data("webauthn.get", challenge_b64, origin);
        let signature = self.sign_assertion(&auth_data, &client_data_raw);
        json!({
            "id": B64URL.encode(&self.credential_id),
            "rawId": B64URL.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": B64URL.encode(&auth_data),
                "signature": B64URL.encode(signature),
                "clientDataJSON": client_data_json,
                "userHandle": user_handle.map(|handle| B64URL.encode(handle)),
            },
            "clientExtensionResults": {},
        })
    }

    fn cose_pubkey(&self) -> Vec<u8> {
        cbor_map(vec![
            (cbor_uint(1), cbor_uint(1)),
            (cbor_uint(3), cbor_nint(-8)),
            (cbor_nint(-1), cbor_uint(6)),
            (
                cbor_nint(-2),
                cbor_bytes(&self.sk.verifying_key().to_bytes()),
            ),
        ])
    }

    fn auth_data_register(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&Sha256::digest("example.com".as_bytes()));
        buf.push(self.flags | FLAG_AT);
        buf.extend_from_slice(&self.counter.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.credential_id);
        buf.extend_from_slice(&self.cose_pubkey());
        buf
    }

    fn auth_data_authenticate(&mut self, counter: Option<u32>) -> Vec<u8> {
        let count = match counter {
            Some(count) => count,
            None => {
                self.counter += 1;
                self.counter
            }
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&Sha256::digest("example.com".as_bytes()));
        buf.push(self.flags);
        buf.extend_from_slice(&count.to_be_bytes());
        buf
    }

    fn attestation_object(&self) -> Vec<u8> {
        cbor_map(vec![
            (cbor_text("fmt"), cbor_text("none")),
            (cbor_text("attStmt"), cbor_map(Vec::new())),
            (
                cbor_text("authData"),
                cbor_bytes(&self.auth_data_register()),
            ),
        ])
    }

    fn sign_assertion(&self, auth_data: &[u8], client_data_json_raw: &[u8]) -> Vec<u8> {
        let client_data_hash = Sha256::digest(client_data_json_raw);
        let mut message = Vec::with_capacity(auth_data.len() + 32);
        message.extend_from_slice(auth_data);
        message.extend_from_slice(&client_data_hash);
        self.sk.sign(&message).to_bytes().to_vec()
    }
}

fn cbor_type(major: u8, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    match len {
        0..=23 => out.push((major << 5) | len as u8),
        24..=0xff => out.extend_from_slice(&[(major << 5) | 24, len as u8]),
        0x100..=0xffff => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    out
}

fn cbor_uint(value: u64) -> Vec<u8> {
    cbor_type(0, value)
}

fn cbor_nint(value: i64) -> Vec<u8> {
    assert!(value < 0);
    cbor_type(1, (-1 - value) as u64)
}

fn cbor_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = cbor_type(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn cbor_text(value: &str) -> Vec<u8> {
    let mut out = cbor_type(3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

fn cbor_map(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut out = cbor_type(5, entries.len() as u64);
    for (key, value) in entries {
        out.extend_from_slice(&key);
        out.extend_from_slice(&value);
    }
    out
}

fn client_data(kind: &str, challenge_b64: &str, origin: &str) -> (Vec<u8>, String) {
    let raw = format!(
        r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes();
    let encoded = B64URL.encode(&raw);
    (raw, encoded)
}
