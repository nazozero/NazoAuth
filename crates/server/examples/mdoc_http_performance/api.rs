//! Native port measurements and actual SignerPort-to-VerifierPort interchange.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value as Cbor;
use coset::AsCborValue as _;
use nazo_digital_credentials::{
    CredentialFormat, CredentialPayload, CredentialSignInput, CredentialSignerPort,
    CredentialTrustError, CredentialVerifierPort, HolderBinding, PresentedCredential,
    VerifiedCredential,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{hint::black_box, path::PathBuf, time::Instant};

const DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const NAMESPACE: &str = "org.iso.18013.5.1";
const CLIENT: &str = "https://verifier.example/interop";
const RESPONSE_URI: &str = "https://verifier.example/interop/response";
const NONCE: &str = "synthetic-cross-version-mdoc-nonce";

fn cbor(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn fixture() -> (Value, String) {
    let path = std::env::var_os("NAZO_MDOC_PERF_FIXTURE").expect("shared fixture path");
    let bytes = std::fs::read(path).unwrap();
    let fixture: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(fixture["version"], 2);
    let expiry: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(fixture["expires_at"].clone()).unwrap();
    assert!(
        expiry > chrono::Utc::now(),
        "regenerate the expired shared fixture"
    );
    (fixture, hex::encode(Sha256::digest(bytes)))
}

fn holder(fixture: &Value) -> SigningKey {
    SigningKey::from_slice(
        &serde_json::from_value::<Vec<u8>>(fixture["holder_private_key"].clone()).unwrap(),
    )
    .unwrap()
}

fn input(fixture: &Value) -> CredentialSignInput {
    let key = holder(fixture);
    let point = key.verifying_key().to_sec1_point(false);
    CredentialSignInput {
        payload: CredentialPayload {
            format: CredentialFormat::MsoMdoc,
            issuer: "https://issuer.example".into(),
            configuration_id: "synthetic-native-mdoc".into(),
            credential_type: DOCTYPE.into(),
            subject_claims: json!({(NAMESPACE): {"given_name":"Ada", "age":42, "issuing_country":"US"}}),
            holder_binding: Some(HolderBinding::Jwk {
                jwk: json!({"kty":"EC", "crv":"P-256", "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())}),
            }),
        },
        issued_at: serde_json::from_value(fixture["issued_at"].clone()).unwrap(),
        expires_at: serde_json::from_value(fixture["expires_at"].clone()).unwrap(),
        status: None,
    }
}

fn transcript(nonce: &str) -> Vec<u8> {
    let info = Cbor::Array(vec![
        CLIENT.into(),
        nonce.into(),
        Cbor::Null,
        RESPONSE_URI.into(),
    ]);
    cbor(&Cbor::Array(vec![
        Cbor::Null,
        Cbor::Null,
        Cbor::Array(vec![
            "OpenID4VPHandover".into(),
            Cbor::Bytes(Sha256::digest(cbor(&info)).to_vec()),
        ]),
    ]))
}

/// Independent wallet framing. The complete IssuerSigned result is spliced
/// verbatim into the response, including every original Tag24 and COSE byte.
pub(crate) fn present(
    issuer_signed: &[u8],
    holder: &SigningKey,
    transcript: &[u8],
) -> (Vec<u8>, usize) {
    let namespaces = Cbor::Tag(24, Box::new(Cbor::Bytes(cbor(&Cbor::Map(vec![])))));
    let mut authentication = vec![0x84];
    authentication.extend(cbor(&"DeviceAuthentication".into()));
    authentication.extend_from_slice(transcript);
    authentication.extend(cbor(&DOCTYPE.into()));
    authentication.extend(cbor(&namespaces));
    let payload = cbor(&Cbor::Tag(24, Box::new(Cbor::Bytes(authentication))));
    let signature = coset::CoseSign1Builder::new()
        .protected(
            coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES256)
                .build(),
        )
        .create_detached_signature(&payload, &[], |input| {
            let signature: Signature = holder.sign(input);
            signature.to_bytes().to_vec()
        })
        .build();
    let device = Cbor::Map(vec![
        (
            "deviceAuth".into(),
            Cbor::Map(vec![(
                "deviceSignature".into(),
                signature.to_cbor_value().unwrap(),
            )]),
        ),
        ("nameSpaces".into(), namespaces),
    ]);
    let mut response = vec![0xa3]; // DeviceResponse map(3).
    for value in [
        Cbor::Text("status".into()),
        0.into(),
        Cbor::Text("version".into()),
        "1.0".into(),
        "documents".into(),
    ] {
        response.extend(cbor(&value));
    }
    response.extend([0x81, 0xa3]); // One Document, map(3).
    response.extend(cbor(&"docType".into()));
    response.extend(cbor(&DOCTYPE.into()));
    response.extend(cbor(&"deviceSigned".into()));
    response.extend(cbor(&device));
    response.extend(cbor(&"issuerSigned".into()));
    let offset = response.len();
    response.extend_from_slice(issuer_signed);
    assert_eq!(
        &response[offset..offset + issuer_signed.len()],
        issuer_signed
    );
    (response, offset)
}

fn presented<'a>(
    encoded: &'a str,
    transcript: &'a [u8],
    nonce: &'a str,
) -> PresentedCredential<'a> {
    PresentedCredential {
        format: CredentialFormat::MsoMdoc,
        encoded: encoded.into(),
        expected_nonce: nonce.into(),
        expected_audience: CLIENT.into(),
        mdoc_session_transcript: Some(transcript.into()),
        additional_trust_anchors: [].as_slice().into(),
    }
}

fn check_verified(value: &VerifiedCredential) {
    assert_eq!(value.format, CredentialFormat::MsoMdoc);
    assert_eq!(value.credential_type, DOCTYPE);
    assert!(value.holder_key.is_some());
    assert!(value.status.is_none());
    assert_eq!(value.claims[NAMESPACE]["given_name"], "Ada");
    assert_eq!(value.claims[NAMESPACE]["age"], 42);
}

fn write_result(variable: &str, value: &Value) {
    let path = PathBuf::from(std::env::var_os(variable).expect("explicit output path"));
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

pub(crate) async fn export() {
    let (fixture, fixture_hash) = fixture();
    let crypto = crate::native_crypto::create(crate::measurement::load_keys(&fixture).await);
    let issued = crypto.sign(&input(&fixture)).await.unwrap();
    let issuer_bytes = URL_SAFE_NO_PAD.decode(&issued).unwrap();
    let transcript = transcript(NONCE);
    let (response, offset) = present(&issuer_bytes, &holder(&fixture), &transcript);
    let encoded = URL_SAFE_NO_PAD.encode(&response);
    let own = crypto
        .verify(&presented(&encoded, &transcript, NONCE))
        .await
        .unwrap();
    check_verified(&own);
    write_result(
        "NAZO_MDOC_INTEROP_OUTPUT",
        &json!({
            "operation":"actual native CredentialSignerPort::sign output; independently framed wallet presentation",
            "source_variant":std::env::var("NAZO_MDOC_HTTP_VARIANT").unwrap_or_default(),
            "source_revision":std::env::var("NAZO_MDOC_HTTP_REVISION").unwrap_or_default(),
            "fixture_sha256":fixture_hash, "issuer_signed":issued,
            "issuer_signed_sha256":hex::encode(Sha256::digest(&issuer_bytes)),
            "issuer_signed_offset":offset, "issuer_signed_bytes":issuer_bytes.len(),
            "presentation":encoded, "presentation_sha256":hex::encode(Sha256::digest(&response)),
            "transcript":URL_SAFE_NO_PAD.encode(&transcript), "nonce":NONCE,
            "self_verified":true, "issuer_bytes_preserved":true,
            "certificate_revocation":"Required; synthetic Good operator snapshot",
            "third_party_wallet_tested":false
        }),
    );
}

pub(crate) async fn verify_export() {
    let (fixture, fixture_hash) = fixture();
    let interchange: Value = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("NAZO_MDOC_INTEROP_INPUT").expect("exported issuer output"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(interchange["fixture_sha256"], fixture_hash);
    let source_variant = interchange["source_variant"].as_str().unwrap();
    let verifier_variant = std::env::var("NAZO_MDOC_HTTP_VARIANT").expect("verifier identity");
    assert!(!source_variant.is_empty() && !verifier_variant.is_empty());
    assert_ne!(
        source_variant, verifier_variant,
        "cross-version verification requires distinct variants"
    );
    let issuer = URL_SAFE_NO_PAD
        .decode(interchange["issuer_signed"].as_str().unwrap())
        .unwrap();
    let encoded = interchange["presentation"].as_str().unwrap();
    let response = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    let offset = usize::try_from(interchange["issuer_signed_offset"].as_u64().unwrap()).unwrap();
    assert_eq!(&response[offset..offset + issuer.len()], issuer);
    assert_eq!(
        interchange["issuer_signed_sha256"],
        hex::encode(Sha256::digest(&issuer))
    );
    let expected_transcript = transcript(NONCE);
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(interchange["transcript"].as_str().unwrap())
            .unwrap(),
        expected_transcript
    );
    let crypto = crate::native_crypto::create(crate::measurement::load_keys(&fixture).await);
    let result = crypto
        .verify(&presented(encoded, &expected_transcript, NONCE))
        .await;
    if let Ok(ref verified) = result {
        check_verified(verified);
    }
    let wrong_transcript = transcript("tampered-verifier-nonce");
    let changed = crypto
        .verify(&presented(
            encoded,
            &wrong_transcript,
            "tampered-verifier-nonce",
        ))
        .await;
    let wrong_session_rejected = changed == Err(CredentialTrustError::InvalidSessionBinding);
    write_result(
        "NAZO_MDOC_INTEROP_OUTPUT",
        &json!({
            "source_variant":interchange["source_variant"], "source_revision":interchange["source_revision"],
            "verifier_variant":std::env::var("NAZO_MDOC_HTTP_VARIANT").unwrap_or_default(),
            "verifier_revision":std::env::var("NAZO_MDOC_HTTP_REVISION").unwrap_or_default(),
            "fixture_sha256":fixture_hash, "issuer_signed_sha256":interchange["issuer_signed_sha256"],
            "presentation_sha256":hex::encode(Sha256::digest(response)),
            "issuer_bytes_preserved":true, "verified":result.is_ok(),
            "error":result.as_ref().err().map(ToString::to_string),
            "wrong_session_rejected":wrong_session_rejected,
            "certificate_revocation":"Required; synthetic Good operator snapshot", "third_party_wallet_tested":false
        }),
    );
    assert!(
        result.is_ok(),
        "actual issued credential failed cross-version verification: {result:?}"
    );
    assert!(wrong_session_rejected);
}

fn summarize(samples: &[u64]) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |p: usize| sorted[(sorted.len() * p).div_ceil(100) - 1];
    json!({"count":sorted.len(), "p50_ns":percentile(50), "p95_ns":percentile(95), "p99_ns":percentile(99),
        "mean_ns":sorted.iter().map(|n| u128::from(*n)).sum::<u128>() as f64 / sorted.len() as f64,
        "min_ns":sorted[0], "max_ns":sorted[sorted.len()-1]})
}

fn require_release_build() {
    if cfg!(debug_assertions) {
        std::panic::panic_any("measure native APIs with a release build");
    }
}

pub(crate) async fn measure() {
    require_release_build();
    let (fixture, fixture_hash) = fixture();
    let count =
        std::env::var("NAZO_MDOC_API_SAMPLES").map_or(2_000, |v| v.parse::<usize>().unwrap());
    assert!(count >= 1_000);
    let crypto = crate::native_crypto::create(crate::measurement::load_keys(&fixture).await);
    let input = input(&fixture);
    let encoded = fixture["encoded"].as_str().unwrap();
    let transcript: Vec<u8> = serde_json::from_value(fixture["transcript"].clone()).unwrap();
    let presentation = PresentedCredential {
        expected_audience: "https://verifier.example".into(),
        ..presented(encoded, &transcript, "verifier-nonce")
    };
    for _ in 0..100 {
        black_box(crypto.sign(&input).await.unwrap());
        check_verified(&crypto.verify(&presentation).await.unwrap());
    }
    let started_at = chrono::Utc::now();
    let mut signing = Vec::with_capacity(count);
    let mut verification = Vec::with_capacity(count);
    for _ in 0..count {
        let start = Instant::now();
        black_box(crypto.sign(black_box(&input)).await.unwrap());
        signing.push(u64::try_from(start.elapsed().as_nanos()).unwrap());
        let start = Instant::now();
        let verified = crypto.verify(black_box(&presentation)).await.unwrap();
        verification.push(u64::try_from(start.elapsed().as_nanos()).unwrap());
        check_verified(&verified);
        black_box(verified);
    }
    write_result(
        "NAZO_MDOC_API_OUTPUT",
        &json!({
            "scope":"actual native CredentialSignerPort and CredentialVerifierPort; no HTTP/database; same sealed keyset and native signing adapter",
            "certificate_revocation":"Required; synthetic Good operator snapshot; MSO status absent",
            "inputs":{"sign":"three claims: given_name, age, issuing_country", "verify":"shared two-claim DeviceResponse: given_name, age"},
            "output_drop_timing":{"sign":"returned String dropped inside timed interval", "verify":"verified result assertions and drop outside timed interval"},
            "clock":"std::time::Instant elapsed wall time", "concurrency":1, "warmup_per_operation":100,
            "fixture_sha256":fixture_hash, "started_at":started_at, "completed_at":chrono::Utc::now(),
            "variant":std::env::var("NAZO_MDOC_HTTP_VARIANT").unwrap_or_default(),
            "revision":std::env::var("NAZO_MDOC_HTTP_REVISION").unwrap_or_default(),
        "panic_strategy":if cfg!(panic = "unwind") { "unwind" } else { "abort" },
            "sign":summarize(&signing), "verify":summarize(&verification),
            "sign_samples_ns":signing, "verify_samples_ns":verification,
        "valid_performance_comparison":signing.len() == count && verification.len() == count
        }),
    );
}
