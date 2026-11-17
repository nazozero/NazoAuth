//! Comparable application-port measurements; no HTTP, database or status server.
//! The shared fixture contains only newly generated, synthetic test key material.
use super::*;
use nazo_key_management::{PersistedSigningKeyset, SigningKeyWrappingKeyRing};
use std::{hint::black_box, path::PathBuf, time::Instant};

fn settings() -> KeySettings {
    KeySettings {
        rotation_interval: jiff::SignedDuration::from_hours((1) * 24),
        prepublish_window: jiff::SignedDuration::from_hours(1),
        verification_grace: jiff::SignedDuration::from_hours(1),
    }
}

fn wrapping_keys(key: [u8; 32]) -> SigningKeyWrappingKeyRing {
    SigningKeyWrappingKeyRing::new("synthetic-benchmark-only", key, None).unwrap()
}

fn random_key() -> [u8; 32] {
    // rand's ThreadRng is a cryptographic generator seeded by the OS. Returning
    // the generated array directly also keeps static analysis on the RNG source.
    rand::random()
}

async fn create_fixture() -> Value {
    use p256::elliptic_curve::Generate as _;
    let wrapping_key = random_key();
    let holder_secret = p256::SecretKey::generate();
    let holder = SigningKey::from_slice(&holder_secret.to_bytes()).unwrap();
    let tenant_id = uuid::Uuid::now_v7();
    let repository =
        Arc::new(nazo_key_management::test_support::MemorySigningKeyRepository::default());
    let keyset = KeyManager::load_or_create_database(
        settings(),
        None,
        tenant_id,
        repository.clone(),
        wrapping_keys(wrapping_key),
    )
    .await
    .unwrap();
    let kid = keyset
        .database_register_local(LocalKeyRegistration {
            algorithm: Algorithm::ES256,
            purposes: [
                nazo_auth::SigningPurpose::Credential,
                nazo_auth::SigningPurpose::PresentationRequest,
            ]
            .into_iter()
            .collect(),
        })
        .await
        .unwrap();
    let leaf_key =
        KeyPair::from_pem(&keyset.database_local_private_key_pem(&kid).unwrap()).unwrap();
    let certs = certificate_fixture_with_key("issuer.example", leaf_key);
    let issued_at = jiff::Timestamp::now();
    let (encoded, transcript) =
        valid_mdoc_presentation_with_holder(&certs, issued_at, None, &holder);
    let record = repository.snapshot().unwrap();
    json!({
        "version": 2,
        "wrapping_key": wrapping_key,
        "holder_private_key": holder_secret.to_bytes().as_slice(),
        "data_encryption_key": random_key(),
        "tenant_id": tenant_id,
        "kid": kid,
        "issued_at": issued_at,
        "expires_at": issued_at + jiff::SignedDuration::from_mins(50),
        "record": {
            "revision": record.revision,
            "public_metadata": record.public_metadata,
            "encrypted_private_material": record.encrypted_private_material,
            "wrapping_key_id": record.wrapping_key_id,
        },
        "ca_der": certs.ca_der,
        "ca_pem": certs.ca_pem,
        "leaf_der": certs.leaf_der,
        "leaf_pem": certs.leaf_pem,
        "encoded": encoded,
        "transcript": transcript,
    })
}

async fn load_fixture(fixture: &Value) -> Openid4vcCredentialCrypto {
    assert_eq!(fixture["version"], 2);
    let repository =
        Arc::new(nazo_key_management::test_support::MemorySigningKeyRepository::default());
    let record = &fixture["record"];
    repository.replace(Some(PersistedSigningKeyset {
        revision: record["revision"].as_i64().unwrap(),
        public_metadata: record["public_metadata"].clone(),
        encrypted_private_material: serde_json::from_value(
            record["encrypted_private_material"].clone(),
        )
        .unwrap(),
        wrapping_key_id: record["wrapping_key_id"].as_str().unwrap().into(),
    }));
    let keyset = KeyManager::load_or_create_database(
        settings(),
        None,
        serde_json::from_value(fixture["tenant_id"].clone()).unwrap(),
        repository,
        wrapping_keys(serde_json::from_value(fixture["wrapping_key"].clone()).unwrap()),
    )
    .await
    .unwrap();
    let leaf_key = KeyPair::from_pem(
        &keyset
            .database_local_private_key_pem(fixture["kid"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let certs = CertificateFixture {
        ca_der: serde_json::from_value(fixture["ca_der"].clone()).unwrap(),
        ca_pem: fixture["ca_pem"].as_str().unwrap().into(),
        leaf_der: serde_json::from_value(fixture["leaf_der"].clone()).unwrap(),
        leaf_pem: fixture["leaf_pem"].as_str().unwrap().into(),
        leaf_key,
    };
    crypto_with_certificate(
        keyset,
        &certs,
        crate::policy::Openid4vcRevocationPolicy::Disabled,
    )
}

fn summary(mut samples: Vec<u64>) -> Value {
    samples.sort_unstable();
    let percentile = |numerator: usize| samples[(samples.len() * numerator).div_ceil(100) - 1];
    json!({
        "samples": samples.len(),
        "p50_ns": percentile(50), "p95_ns": percentile(95), "p99_ns": percentile(99),
        "mean_ns": samples.iter().map(|n| *n as u128).sum::<u128>() as f64 / samples.len() as f64,
        "min_ns": samples[0], "max_ns": samples[samples.len() - 1],
        "sorted_samples_ns": samples,
    })
}

fn require_release_build() {
    if cfg!(debug_assertions) {
        std::panic::panic_any("measure with cargo test --release");
    }
}

#[test]
#[ignore = "requires a shared synthetic fixture and an explicit release benchmark run"]
fn mdoc_embedded_api_latency() {
    require_release_build();
    let fixture_path =
        PathBuf::from(std::env::var_os("NAZO_MDOC_PERF_FIXTURE").expect("shared fixture path"));
    let samples = std::env::var("NAZO_MDOC_PERF_SAMPLES")
        .map_or(2_000, |value| value.parse::<usize>().unwrap());
    assert!(samples >= 100);
    futures_executor::block_on(async {
        let fixture = if fixture_path.exists() {
            serde_json::from_slice(&std::fs::read(&fixture_path).unwrap()).unwrap()
        } else {
            let fixture = create_fixture().await;
            std::fs::write(&fixture_path, serde_json::to_vec(&fixture).unwrap()).unwrap();
            fixture
        };
        let crypto = load_fixture(&fixture).await;
        let holder = SigningKey::from_slice(
            &serde_json::from_value::<Vec<u8>>(fixture["holder_private_key"].clone()).unwrap(),
        )
        .unwrap();
        let point = holder.verifying_key().to_sec1_point(false);
        let mut input = mdoc_input(
            Some(HolderBinding::Jwk {
                jwk: json!({
                    "kty":"EC", "crv":"P-256",
                    "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y":URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                }),
            }),
            json!({"org.iso.18013.5.1":{"given_name":"Ada", "age":42, "issuing_country":"US"}}),
        );
        input.issued_at = serde_json::from_value(fixture["issued_at"].clone()).unwrap();
        input.expires_at = serde_json::from_value(fixture["expires_at"].clone()).unwrap();
        assert!(
            input.expires_at > jiff::Timestamp::now(),
            "shared fixture expired; regenerate it and repeat both revisions"
        );
        let transcript: Vec<u8> = serde_json::from_value(fixture["transcript"].clone()).unwrap();
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: fixture["encoded"].as_str().unwrap().into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.as_slice().into()),
            additional_trust_anchors: [].as_slice().into(),
        };
        if std::env::var("NAZO_MDOC_PERF_PREPARE_ONLY").as_deref() == Ok("1") {
            black_box(crypto.sign(&input).await.unwrap());
            black_box(crypto.verify(&presentation).await.unwrap());
            return;
        }
        let output_path = PathBuf::from(
            std::env::var_os("NAZO_MDOC_PERF_OUTPUT").expect("measurement output path"),
        );
        for _ in 0..100 {
            black_box(crypto.sign(&input).await.unwrap());
            black_box(crypto.verify(&presentation).await.unwrap());
        }
        let mut signing = Vec::with_capacity(samples);
        let mut verification = Vec::with_capacity(samples);
        for _ in 0..samples {
            let start = Instant::now();
            black_box(crypto.sign(black_box(&input)).await.unwrap());
            signing.push(u64::try_from(start.elapsed().as_nanos()).unwrap());
            let start = Instant::now();
            black_box(crypto.verify(black_box(&presentation)).await.unwrap());
            verification.push(u64::try_from(start.elapsed().as_nanos()).unwrap());
        }
        let output = json!({
            "scope": "NazoAuth CredentialSignerPort and CredentialVerifierPort; no HTTP; in-memory key repository; certificate revocation disabled; no MSO status",
            "clock": "std::time::Instant elapsed wall time", "concurrency": 1, "warmup_per_operation": 100,
            "fixture_sha256": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(serde_json::to_vec(&fixture).unwrap())),
            "encoded_presentation_bytes": presentation.encoded.len(),
            "sign": summary(signing), "verify": summary(verification),
        });
        std::fs::write(output_path, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    });
}
