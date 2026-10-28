//! End-to-end tests for `packed (x5c)` and `fido-u2f` attestation.
//!
//! Both formats verify the attestation `sig` against the public key
//! of a real X.509 certificate. The tests here synthesise a P-256
//! self-signed cert at runtime using `x509-cert`'s builder, then
//! drive a full registration through the public Webauthn API.
//!
//! These tests complement (do NOT duplicate) the ones in
//! `tests/ceremony_e2e.rs`, which exercises `fmt: "none"` only.

use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ciborium::value::Value as CborValue;
use p256::ecdsa::{Signature as EsSig, SigningKey, signature::Signer};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};
use x509_cert_test::builder::{Builder, CertificateBuilder, profile::BuilderProfile};
use x509_cert_test::der::asn1::OctetString;
use x509_cert_test::der::{Encode, oid::AssociatedOid};
use x509_cert_test::ext::{Criticality, Extension};
use x509_cert_test::name::Name;
use x509_cert_test::serial_number::SerialNumber;
use x509_cert_test::spki::SubjectPublicKeyInfoOwned;
use x509_cert_test::time::Validity;

// ---------- AAGUID extension (custom) ----------------------------------------

/// Thin wrapper that implements x509-cert's ToExtension trait so we can
/// add the FIDO AAGUID extension to a synthetic cert. The on-wire shape
/// is OCTET STRING (16 bytes); the outer OCTET STRING wrapping is done
/// automatically by ToExtension::to_extension.
#[derive(Clone, Debug)]
struct FidoAaguid([u8; 16]);

impl AssociatedOid for FidoAaguid {
    const OID: x509_cert_test::der::oid::ObjectIdentifier =
        x509_cert_test::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
}

impl x509_cert_test::der::Encode for FidoAaguid {
    fn encoded_len(&self) -> x509_cert_test::der::Result<x509_cert_test::der::Length> {
        OctetString::new(self.0.to_vec()).unwrap().encoded_len()
    }
    fn encode(&self, encoder: &mut impl x509_cert_test::der::Writer) -> x509_cert_test::der::Result<()> {
        OctetString::new(self.0.to_vec()).unwrap().encode(encoder)
    }
}

impl Criticality for FidoAaguid {
    fn criticality(&self, _subject: &Name, _exts: &[Extension]) -> bool {
        false
    }
}

/// Deliberately malformed AAGUID extension. Encodes the wrong shape -
/// we use this in a regression test for the "malformed extension is
/// rejected" path. The bytes here are NOT a valid DER OCTET STRING of
/// 16 bytes; the inner tag/length is junk.
#[derive(Clone, Debug)]
struct MalformedAaguid;

impl AssociatedOid for MalformedAaguid {
    const OID: x509_cert_test::der::oid::ObjectIdentifier =
        x509_cert_test::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");
}

impl x509_cert_test::der::Encode for MalformedAaguid {
    fn encoded_len(&self) -> x509_cert_test::der::Result<x509_cert_test::der::Length> {
        // 7 bytes of attacker-chosen junk inside the outer OCTET STRING.
        OctetString::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22])
            .unwrap()
            .encoded_len()
    }
    fn encode(&self, encoder: &mut impl x509_cert_test::der::Writer) -> x509_cert_test::der::Result<()> {
        OctetString::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22])
            .unwrap()
            .encode(encoder)
    }
}

impl Criticality for MalformedAaguid {
    fn criticality(&self, _subject: &Name, _exts: &[Extension]) -> bool {
        false
    }
}

use passkey_auth::{RegistrationResponse, Webauthn};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

struct TestProfile(Name);
impl BuilderProfile for TestProfile {
    fn get_issuer(&self, _: &Name) -> Name { self.0.clone() }
    fn get_subject(&self) -> Name { self.0.clone() }
    fn build_extensions(&self, _: x509_cert_test::spki::SubjectPublicKeyInfoRef<'_>, _: x509_cert_test::spki::SubjectPublicKeyInfoRef<'_>, _: &x509_cert_test::certificate::TbsCertificate) -> x509_cert_test::builder::Result<Vec<Extension>> { Ok(Vec::new()) }
}

// ---------- cert + key bundle ----------------------------------------------

/// A fresh P-256 keypair plus a self-signed DER cert for that key.
/// Used as the attestation cert in tests.
struct CertBundle {
    signing_key: SigningKey,
    cert_der: Vec<u8>,
}

/// Which AAGUID extension (if any) to embed in the test cert.
#[derive(Clone, Copy)]
enum AaguidExt {
    /// No FIDO AAGUID extension on the cert.
    None,
    /// Well-formed extension carrying the given 16 bytes.
    Valid([u8; 16]),
    /// Extension OID is present but the inner OCTET STRING is junk.
    /// Used to test the "must not silently swallow malformed extensions"
    /// path.
    Malformed,
}

impl CertBundle {
    /// Mint a fresh self-signed leaf cert with the requested AAGUID
    /// extension shape.
    fn new(aaguid: AaguidExt) -> Self {
        let signing_key = SigningKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // SubjectPublicKeyInfo for the verifying key, in PKCS8/SEC1 form.
        let pk_der = p256::PublicKey::from(verifying_key)
            .to_public_key_der()
            .expect("p256 pubkey to DER")
            .as_bytes()
            .to_vec();
        let spki =
            SubjectPublicKeyInfoOwned::try_from(pk_der.as_slice()).expect("SPKI from p256 DER");

        let subject = Name::from_str("CN=passkey-auth test attestation")
            .expect("name parse")
            .to_der()
            .expect("name to DER");
        let subject = Name::from_der_slice(&subject);

        // Use Leaf profile (no constraints, no SAN). We are a leaf cert
        // in a one-cert chain; that's all the FIDO format needs.
        let profile = TestProfile(subject);
        let mut builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(60 * 60)).expect("validity"),
            spki,
        )
        .expect("CertificateBuilder::new");

        // Add the FIDO AAGUID extension if requested. ToExtension on
        // FidoAaguid handles the double OCTET STRING wrapping the spec
        // requires (outer wrap done by ToExtension::to_extension, inner
        // wrap done by our Encode impl).
        match aaguid {
            AaguidExt::None => {}
            AaguidExt::Valid(value) => {
                builder
                    .add_extension(&FidoAaguid(value))
                    .expect("add aaguid ext");
            }
            AaguidExt::Malformed => {
                builder
                    .add_extension(&MalformedAaguid)
                    .expect("add malformed aaguid ext");
            }
        }

        let cert: x509_cert_test::Certificate = builder
            .build::<_, p256::ecdsa::DerSignature>(&signing_key)
            .expect("cert build");
        let cert_der = cert.to_der().expect("cert to DER");

        Self {
            signing_key,
            cert_der,
        }
    }
}

// Tiny shim because x509-cert's `from_der` returns a Result we
// always unwrap in this test file.
trait FromDerSlice: Sized {
    fn from_der_slice(der: &[u8]) -> Self;
}
impl FromDerSlice for Name {
    fn from_der_slice(der: &[u8]) -> Self {
        use x509_cert_test::der::Decode;
        Self::from_der(der).expect("Name from DER")
    }
}

// ---------- credential keypair (the one embedded in authData) --------------

/// The credential's own keypair, separate from the attestation cert's.
/// In `packed-x5c` they are different; in `fido-u2f` they are different too.
///
/// The signing key itself is unused in the registration tests (we only
/// need the public coordinates for COSE encoding); the suppression keeps
/// the type ready if a future test wants to sign an assertion too.
struct CredKey {
    #[allow(dead_code)]
    signing_key: SigningKey,
    x: [u8; 32],
    y: [u8; 32],
}

impl CredKey {
    fn new() -> Self {
        let signing_key = SigningKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let vk = signing_key.verifying_key();
        let pt = vk.to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&pt.x().unwrap()[..]);
        y.copy_from_slice(&pt.y().unwrap()[..]);
        Self { signing_key, x, y }
    }

    fn cose_pubkey(&self) -> Vec<u8> {
        // COSE_Key for ES256: { 1: 2, 3: -7, -1: 1, -2: x, -3: y }
        let map = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-7).into()),
            ),
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(1.into()),
            ),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(self.x.to_vec()),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(self.y.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }
}

// ---------- authenticator helpers ------------------------------------------

fn auth_data_register(rp_id: &str, aaguid: [u8; 16], cred_id: &[u8], cose_pk: &[u8]) -> Vec<u8> {
    const FLAG_UP: u8 = 1 << 0;
    const FLAG_UV: u8 = 1 << 2;
    const FLAG_AT: u8 = 1 << 6;
    let mut buf = Vec::new();
    buf.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    buf.push(FLAG_UP | FLAG_UV | FLAG_AT);
    buf.extend_from_slice(&0u32.to_be_bytes()); // counter
    buf.extend_from_slice(&aaguid);
    buf.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(cred_id);
    buf.extend_from_slice(cose_pk);
    buf
}

fn client_data(kind: &str, challenge_b64: &str, origin: &str) -> (Vec<u8>, String) {
    let json = format!(
        r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    );
    let raw = json.into_bytes();
    let enc = B64URL.encode(&raw);
    (raw, enc)
}

// ---------- packed-x5c tests -----------------------------------------------

#[test]
fn packed_x5c_happy_path() {
    let aaguid: [u8; 16] = *b"yubico-test-0001";
    let cert = CertBundle::new(AaguidExt::Valid(aaguid));
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-packed-0001";
    let cose_pk = cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    // Build the packed attestation statement signed by the CERT key
    // (not the credential key) over authData || SHA256(clientDataJSON).
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    let sig: EsSig = cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec!["usb".into()],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let credential = wa
        .finish_registration(&state, &response)
        .expect("packed-x5c registration must succeed");
    assert_eq!(credential.aaguid, aaguid);
}

#[test]
fn packed_x5c_aaguid_mismatch_rejected() {
    let cert_aaguid: [u8; 16] = *b"yubico-test-0001";
    let auth_aaguid: [u8; 16] = *b"different-aaguid";
    let cert = CertBundle::new(AaguidExt::Valid(cert_aaguid));
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-packed-0002";
    let cose_pk = cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, auth_aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    let sig: EsSig = cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let err = wa
        .finish_registration(&state, &response)
        .expect_err("AAGUID mismatch must reject");
    let msg = err.to_string();
    assert!(msg.contains("AAGUID"), "expected AAGUID error, got: {msg}",);
}

#[test]
fn packed_x5c_bad_signature_rejected() {
    let aaguid: [u8; 16] = *b"yubico-test-0001";
    let cert = CertBundle::new(AaguidExt::Valid(aaguid));
    let _wrong_cert = CertBundle::new(AaguidExt::Valid(aaguid)); // different key
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-packed-0003";
    let cose_pk = cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    // Sign with the WRONG key (the other cert's key), so the x5c
    // public key will not verify.
    let sig: EsSig = _wrong_cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let err = wa
        .finish_registration(&state, &response)
        .expect_err("bad x5c sig must reject");
    assert!(matches!(err, passkey_auth::Error::BadSignature,));
}

// ---------- fido-u2f tests -------------------------------------------------

#[test]
fn fido_u2f_happy_path() {
    let cert = CertBundle::new(AaguidExt::None); // U2F format does NOT include AAGUID ext
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-u2f-0001";
    let cose_pk = cred.cose_pubkey();
    let aaguid = [0u8; 16]; // U2F authenticators always emit zero AAGUID
    let auth_data = auth_data_register(RP_ID, aaguid, cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    // U2F pre-image: 0x00 || rpIdHash || cdjHash || credId || pubKey-SEC1
    let mut pre_image = Vec::new();
    pre_image.push(0x00);
    pre_image.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    pre_image.extend_from_slice(&Sha256::digest(&cdj_raw));
    pre_image.extend_from_slice(cred_id);
    pre_image.push(0x04);
    pre_image.extend_from_slice(&cred.x);
    pre_image.extend_from_slice(&cred.y);

    let sig: EsSig = cert.signing_key.sign(&pre_image);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("fido-u2f".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec!["usb".into()],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let credential = wa
        .finish_registration(&state, &response)
        .expect("fido-u2f registration must succeed");
    assert_eq!(credential.id.as_bytes(), cred_id);
}

#[test]
fn fido_u2f_wrong_credential_pubkey_rejected() {
    let cert = CertBundle::new(AaguidExt::None);
    let real_cred = CredKey::new();
    let bogus_cred = CredKey::new(); // we'll sign the U2F pre-image with the bogus pubkey
    let cred_id: &[u8] = b"cred-u2f-0002";
    // authData carries the REAL credential public key...
    let cose_pk = real_cred.cose_pubkey();
    let auth_data = auth_data_register(RP_ID, [0u8; 16], cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    // ...but we sign over the WRONG pubkey, simulating tampering.
    let mut pre_image = Vec::new();
    pre_image.push(0x00);
    pre_image.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    pre_image.extend_from_slice(&Sha256::digest(&cdj_raw));
    pre_image.extend_from_slice(cred_id);
    pre_image.push(0x04);
    pre_image.extend_from_slice(&bogus_cred.x);
    pre_image.extend_from_slice(&bogus_cred.y);
    let sig: EsSig = cert.signing_key.sign(&pre_image);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("fido-u2f".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    assert!(wa.finish_registration(&state, &response).is_err());
}

// ---------- regression test for malformed AAGUID extension ------------------

/// Without the fix this catches, a cert containing an AAGUID extension
/// whose inner OCTET STRING is junk would parse as "no AAGUID extension"
/// and skip the cert-vs-authData AAGUID match check in verify_packed -
/// letting a malicious cert claim ANY authData AAGUID despite carrying
/// a contradictory one of its own.
///
/// The fix in src/x509.rs propagates the parse error instead of using
/// `.ok()`. This test signs a packed attestation with a cert that
/// carries the AAGUID extension OID but a deliberately-broken inner
/// value, and asserts the registration is rejected outright rather
/// than silently treated as if the extension were absent.
#[test]
fn packed_x5c_malformed_aaguid_rejected() {
    let cert = CertBundle::new(AaguidExt::Malformed);
    let cred = CredKey::new();
    let cred_id: &[u8] = b"cred-malformed-aaguid";
    let cose_pk = cred.cose_pubkey();
    // authData carries SOME AAGUID. The malformed extension means we
    // cannot tell if it matches; the parser must refuse rather than
    // silently accept.
    let auth_data = auth_data_register(RP_ID, *b"any-authd-aaguid", cred_id, &cose_pk);

    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (chal, state) = wa.start_registration(b"u", "alice", "Alice", &[]);
    let (cdj_raw, cdj_b64) = client_data("webauthn.create", &chal.challenge, ORIGIN);

    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&Sha256::digest(&cdj_raw));
    let sig: EsSig = cert.signing_key.sign(&signed);
    let sig_der = sig.to_der().to_bytes().to_vec();

    let att_obj = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![
                (
                    CborValue::Text("alg".into()),
                    CborValue::Integer((-7).into()),
                ),
                (CborValue::Text("sig".into()), CborValue::Bytes(sig_der)),
                (
                    CborValue::Text("x5c".into()),
                    CborValue::Array(vec![CborValue::Bytes(cert.cert_der.clone())]),
                ),
            ]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att_obj, &mut att_bytes).unwrap();

    let response = RegistrationResponse {
        id: B64URL.encode(cred_id),
        transports: vec![],
        attestation_object: B64URL.encode(&att_bytes),
        client_data_json: cdj_b64,
    };

    let err = wa
        .finish_registration(&state, &response)
        .expect_err("malformed AAGUID extension must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("AAGUID") || msg.contains("malformed"),
        "expected malformed/AAGUID error, got: {msg}",
    );
}
