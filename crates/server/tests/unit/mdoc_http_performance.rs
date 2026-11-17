//! Real TCP/HTTP measurements of the production OID4VP response endpoint.
//!
//! Run the standalone example in release mode with the same synthetic fixture on
//! both revisions, from an isolated working directory for native configuration.
//! Required variables: NAZO_MDOC_PERF_FIXTURE, NAZO_MDOC_HTTP_OUTPUT,
//! NAZO_TEST_DATABASE_URL (or DATABASE_URL), and NAZO_TEST_VALKEY_URL (or
//! VALKEY_URL). NAZO_MDOC_HTTP_SAMPLES defaults to 1,000 and must be at least
//! 1,000; NAZO_MDOC_HTTP_WARMUP defaults to 100 and must be at least 100.
//!
//! Setup seeds independent transactions through the real PostgreSQL repository.
//! The measured operation is POST /openid4vp/response/{id}, including reading the
//! complete HTTP response body. A separate, untimed GET checks the persisted
//! verified credential. HTTP errors and failed result checks are never included
//! in successful latency percentiles. Request creation and wallet-side signing
//! are outside the measured interval. The exact same deterministic request
//! corpus is produced from the shared fixture on both revisions.
//! Fixture version 2 supplies OS-generated wrapping, persistence and holder
//! keys, generated once and reused by both revisions rather than hardcoded.
//!
//! Scope: single-tenant facade, production Actix adapter, real PostgreSQL and
//! Valkey bindings, direct_post, ES256 issuer/holder signatures, X.509 path and
//! required operator-snapshot certificate status checks. This does not measure
//! HAIP/JWE, TLS, the native host's tenant router, or remote MSO status fetching.

use actix_web::{App, HttpServer, web};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ciborium::Value as Cbor;
use diesel::{sql_query, sql_types};
use diesel_async::RunQueryDsl as _;
use nazo_digital_credentials::{
    CertificateRevocationEntry, CertificateRevocationSnapshot, CertificateRevocationStatus,
    CredentialFormat, CredentialQuery, DcqlQuery, certificate_identity,
};
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantId};
use nazo_key_management::{
    KeyManager, KeySettings, Openid4vcMaterial, Openid4vcPublicMaterial, PersistedSigningKeyset,
    SigningKeyWrappingKeyRing,
};
use nazo_openid4vp::{
    AuthorizationRequest, ClientIdPrefix, PresentationCreateIdempotency, PresentationCreateOutcome,
    PresentationResult, PresentationStorePort, PresentationTransaction, RequestMethod,
    ResponseMode,
};
use nazo_postgres::{
    TenantBoundaryDefinition, TenantDirectoryRepository, TenantProvisioningRequest,
};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

const ISSUER: &str = "https://issuer.example";
const HOST: &str = "issuer.example";
const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NAMESPACE: &str = "org.iso.18013.5.1";

struct Case {
    transaction: PresentationTransaction,
    body: String,
}

fn cbor(value: &Cbor) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).unwrap();
    encoded
}

fn cbor_field<'a>(value: &'a Cbor, name: &str) -> &'a Cbor {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1
}

fn derive_token(fixture_digest: &[u8], label: &[u8], index: usize) -> String {
    let mut digest = Sha256::new();
    digest.update(fixture_digest);
    digest.update(label);
    digest.update(u64::try_from(index).unwrap().to_be_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

/// Independent synthetic wallet encoder for the Final B.2.6.1 handover and
/// ISO DeviceAuthenticationBytes. Only the device proof changes; the complete
/// original IssuerSigned encoding is copied byte for byte from the fixture.
fn prepare_cases(fixture: &Value, digest: &[u8], count: usize) -> Vec<Case> {
    let bytes = URL_SAFE_NO_PAD
        .decode(fixture["encoded"].as_str().unwrap())
        .unwrap();
    let original: Cbor = ciborium::from_reader(bytes.as_slice()).unwrap();
    // This synthetic fixture must round-trip exactly before a Value encoding
    // can be used to locate a subtree. The wallet then uses the received slice,
    // never the re-encoded IssuerSigned value, in every generated response.
    assert_eq!(cbor(&original), bytes);
    assert_eq!(
        cbor_field(&original, "documents").as_array().unwrap().len(),
        1
    );
    let document = &cbor_field(&original, "documents").as_array().unwrap()[0];
    assert_eq!(cbor_field(document, "docType").as_text(), Some(DOC_TYPE));
    assert_eq!(
        cbor_field(cbor_field(document, "deviceSigned"), "nameSpaces"),
        &Cbor::Tag(24, Box::new(Cbor::Bytes(cbor(&Cbor::Map(vec![]))))),
        "the shared wallet workload uses empty device namespaces"
    );
    let issuer_encoding = cbor(cbor_field(document, "issuerSigned"));
    let positions: Vec<_> = bytes
        .windows(issuer_encoding.len())
        .enumerate()
        .filter_map(|(index, window)| (window == issuer_encoding).then_some(index))
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "unambiguous original IssuerSigned slice"
    );
    let issuer_signed = &bytes[positions[0]..positions[0] + issuer_encoding.len()];
    let holder_private_key: Vec<u8> =
        serde_json::from_value(fixture["holder_private_key"].clone()).unwrap();
    assert_eq!(holder_private_key.len(), 32);
    let holder = SigningKey::from_slice(&holder_private_key).unwrap();
    let created_at: DateTime<Utc> = serde_json::from_value(fixture["issued_at"].clone()).unwrap();
    let expires_at: DateTime<Utc> = serde_json::from_value(fixture["expires_at"].clone()).unwrap();
    assert!(
        expires_at > Utc::now() + chrono::Duration::minutes(1),
        "regenerate an expired fixture and repeat both revisions"
    );

    (0..count)
        .map(|index| {
            let id = Uuid::from_u128(0x019f_0000_0000_7000_8000_0000_0000_0000 + index as u128);
            let response_uri = format!("{ISSUER}/openid4vp/response/{id}");
            let request = AuthorizationRequest {
                client_id: response_uri.clone(),
                response_type: "vp_token".into(),
                response_mode: ResponseMode::DirectPost,
                response_uri,
                nonce: derive_token(digest, b"nonce", index),
                state: derive_token(digest, b"state", index),
                dcql_query: DcqlQuery {
                    credentials: vec![CredentialQuery {
                        id: "mdoc".into(),
                        format: CredentialFormat::MsoMdoc,
                        multiple: false,
                        meta: Some(json!({"doctype_value": DOC_TYPE})),
                        claims: None,
                        claim_sets: None,
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                    }],
                    credential_sets: None,
                },
                client_metadata: None,
                verifier_info: None,
                transaction_data: None,
                wallet_nonce: None,
            };
            request.validate().unwrap();
            let handover_info = Cbor::Array(vec![
                request.client_id.clone().into(),
                request.nonce.clone().into(),
                Cbor::Null,
                request.response_uri.clone().into(),
            ]);
            let transcript = Cbor::Array(vec![
                Cbor::Null,
                Cbor::Null,
                Cbor::Array(vec![
                    "OpenID4VPHandover".into(),
                    Cbor::Bytes(Sha256::digest(cbor(&handover_info)).to_vec()),
                ]),
            ]);
            let (response, issuer_offset) =
                crate::api::present(issuer_signed, &holder, &cbor(&transcript));
            assert_eq!(
                &response[issuer_offset..issuer_offset + issuer_signed.len()],
                issuer_signed
            );
            let vp_token = json!({"mdoc": [URL_SAFE_NO_PAD.encode(response)]});
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("state", &request.state)
                .append_pair("vp_token", &serde_json::to_string(&vp_token).unwrap())
                .finish();
            Case {
                transaction: PresentationTransaction {
                    id,
                    client_id_prefix: ClientIdPrefix::RedirectUri,
                    request_method: RequestMethod::UrlQuery,
                    wallet_authorization_endpoint: "https://wallet.example/authorize".into(),
                    request,
                    request_object: None,
                    request_uri: None,
                    openid4vc_trust_policy_binding_id: None,
                    openid4vc_trust_policy_resource_id: None,
                    openid4vc_trust_policy_digest: None,
                    response_encryption_private_key: None,
                    created_at,
                    expires_at,
                },
                body,
            }
        })
        .collect()
}

pub(crate) async fn load_keys(fixture: &Value) -> KeyManager {
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
    let wrapping_key: [u8; 32] = serde_json::from_value(fixture["wrapping_key"].clone()).unwrap();
    let keys = KeyManager::load_or_create_database(
        KeySettings {
            rotation_interval: chrono::Duration::days(1),
            prepublish_window: chrono::Duration::hours(1),
            verification_grace: chrono::Duration::hours(1),
        },
        None,
        serde_json::from_value(fixture["tenant_id"].clone()).unwrap(),
        repository,
        SigningKeyWrappingKeyRing::new("synthetic-benchmark-only", wrapping_key, None).unwrap(),
    )
    .await
    .unwrap();
    let leaf: Vec<u8> = serde_json::from_value(fixture["leaf_der"].clone()).unwrap();
    let ca: Vec<u8> = serde_json::from_value(fixture["ca_der"].clone()).unwrap();
    let snapshot = CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: serde_json::from_value(fixture["issued_at"].clone()).unwrap(),
        next_update: serde_json::from_value(fixture["expires_at"].clone()).unwrap(),
        entries: [&leaf, &ca]
            .into_iter()
            .map(|certificate| CertificateRevocationEntry {
                issuer: ISSUER.into(),
                certificate: certificate_identity(certificate),
                status: CertificateRevocationStatus::Good,
                revoked_at: None,
            })
            .collect(),
    };
    snapshot.validate_freshness_at(Utc::now()).unwrap();
    keys.set_openid4vc_material_for_test(Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid: fixture["kid"].as_str().unwrap().into(),
            certificate_chain_pem: format!(
                "{}{}",
                fixture["leaf_pem"].as_str().unwrap(),
                fixture["ca_pem"].as_str().unwrap()
            ),
            trust_anchors_pem: fixture["ca_pem"].as_str().unwrap().into(),
            revocation_snapshot: Some(snapshot),
        },
        iaca_private_materials: Default::default(),
    });
    keys
}

async fn infrastructure(
    fixture: &Value,
    database_url: &str,
    valkey_url: &str,
) -> crate::test_support::TestInfrastructure {
    nazo_postgres::run_pending_migrations(database_url)
        .await
        .unwrap();
    let pool = nazo_postgres::create_pool(database_url, 4).unwrap();
    let tenant_id =
        TenantId::new(serde_json::from_value(fixture["tenant_id"].clone()).unwrap()).unwrap();
    let tenant = TenantContext {
        tenant_id,
        realm_id: RealmId::new(Uuid::from_u128(0x019f_0000_0000_7000_8000_0000_0000_0101)).unwrap(),
        organization_id: OrganizationId::new(Uuid::from_u128(
            0x019f_0000_0000_7000_8000_0000_0000_0102,
        ))
        .unwrap(),
    };
    let directory = TenantDirectoryRepository::new(pool.clone());
    directory
        .provision_tenant_binding(
            directory.current_revision().await.unwrap(),
            TenantProvisioningRequest {
                tenant: TenantBoundaryDefinition {
                    id: tenant.tenant_id,
                    slug: "mdoc-http-perf".into(),
                    display_name: "Synthetic mdoc benchmark".into(),
                },
                realm: TenantBoundaryDefinition {
                    id: tenant.realm_id,
                    slug: "mdoc-http-perf".into(),
                    display_name: "Synthetic mdoc benchmark".into(),
                },
                organization: TenantBoundaryDefinition {
                    id: tenant.organization_id,
                    slug: "mdoc-http-perf".into(),
                    display_name: "Synthetic mdoc benchmark".into(),
                },
                binding: TenantDirectoryBinding {
                    tenant,
                    runtime_revision: 1,
                    issuer: ISSUER.into(),
                    external_host: HOST.into(),
                },
            },
        )
        .await
        .unwrap();
    let valkey = nazo_valkey::test_support::connect(valkey_url, Duration::from_secs(5))
        .await
        .unwrap();
    let mut settings =
        crate::settings::Settings::from_config(&crate::config::ConfigSource::load().unwrap())
            .unwrap();
    settings.tenant.context = tenant;
    settings.endpoint.issuer = ISSUER.into();
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.example".into();
    settings.session.cookie_secure = true;
    settings.modules.register_openid4vp_routes = true;
    settings.modules.enable_openid4vp_verifier = true;
    settings.modules.register_openid4vci_routes = false;
    settings.modules.enable_openid4vci_issuer = false;
    let data_key: [u8; 32] =
        serde_json::from_value(fixture["data_encryption_key"].clone()).unwrap();
    settings.openid4vc.data_encryption_key = Some(data_key);
    settings.openid4vc.verifier_management_token =
        Some(derive_token(&data_key, b"benchmark-management-token", 0));
    settings.openid4vc.wallet_authorization_origins = vec!["https://wallet.example".into()];
    settings.openid4vc.transaction_ttl_seconds = 3600;
    settings.openid4vc.revocation_policy =
        nazo_oauth_server::policy::Openid4vcRevocationPolicy::Required;
    crate::test_support::TestInfrastructure {
        diesel_db: pool,
        valkey,
        settings: Arc::new(settings),
        keyset: load_keys(fixture).await,
    }
}

async fn seed_transactions(state: &crate::test_support::TestInfrastructure, cases: &[Case]) {
    let tenant = state.settings.tenant.context.tenant_id.as_uuid();
    let data_key = state.settings.openid4vc.data_encryption_key.unwrap();
    let store = nazo_postgres::Openid4vpRepository::new(state.diesel_db.clone(), tenant, data_key);
    let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
    // Only replace this synthetic fixture's transaction IDs, never other tenant data.
    sql_query("DELETE FROM openid4vp_transactions WHERE tenant_id = $1 AND id = ANY($2)")
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Array<sql_types::Uuid>, _>(
            cases
                .iter()
                .map(|case| case.transaction.id)
                .collect::<Vec<_>>(),
        )
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    for case in cases {
        let transaction = &case.transaction;
        let normalized = nazo_operator_protocol::Openid4vpNormalizedCreateRequest {
            wallet_authorization_endpoint: transaction.wallet_authorization_endpoint.clone(),
            dcql_query: serde_json::to_value(&transaction.request.dcql_query).unwrap(),
            haip: false,
            client_id_prefix: transaction.client_id_prefix.as_str().into(),
            request_method: transaction.request_method.as_str().into(),
            response_mode: transaction.request.response_mode.as_str().into(),
            transaction_data: None,
            openid4vc_trust_policy_resource_id: None,
            openid4vc_trust_policy_digest: None,
        };
        let (canonical_request, request_sha256) =
            nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized)
                .unwrap();
        assert!(matches!(
            store
                .create(
                    transaction,
                    PresentationCreateIdempotency {
                        request_jti: &transaction.id.to_string(),
                        request_sha256: &request_sha256,
                        canonical_request: &canonical_request,
                    }
                )
                .await
                .unwrap(),
            PresentationCreateOutcome::Created
        ));
    }
}

fn summarize(samples: &[u64]) -> Value {
    if samples.is_empty() {
        return Value::Null;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |p: usize| sorted[(sorted.len() * p).div_ceil(100) - 1];
    json!({"count": sorted.len(), "p50_ns": percentile(50), "p95_ns": percentile(95), "p99_ns": percentile(99),
        "min_ns": sorted[0], "max_ns": sorted[sorted.len() - 1],
        "mean_ns": sorted.iter().map(|value| *value as u128).sum::<u128>() as f64 / sorted.len() as f64})
}

fn persisted_result_matches(result: &PresentationResult, case: &Case) -> bool {
    result.transaction_id == case.transaction.id
        && result.credentials.len() == 1
        && result.credentials[0].format == CredentialFormat::MsoMdoc
        && result.credentials[0].credential_type == DOC_TYPE
        && result.credentials[0].holder_key.is_some()
        && result.credentials[0].status.is_none()
        && result.credentials[0].claims[NAMESPACE]["given_name"] == "Ada"
        && result.credentials[0].claims[NAMESPACE]["age"] == 42
}

fn require_release_build() {
    if cfg!(debug_assertions) {
        std::panic::panic_any(
            "measure HTTP with cargo run --release --example mdoc_http_performance",
        );
    }
}

pub(crate) async fn run() {
    require_release_build();
    let fixture_path = PathBuf::from(
        std::env::var_os("NAZO_MDOC_PERF_FIXTURE").expect("shared synthetic fixture"),
    );
    let output_path =
        PathBuf::from(std::env::var_os("NAZO_MDOC_HTTP_OUTPUT").expect("HTTP output JSON path"));
    let sample_count = std::env::var("NAZO_MDOC_HTTP_SAMPLES")
        .map_or(1000, |value| value.parse::<usize>().unwrap());
    let warmup =
        std::env::var("NAZO_MDOC_HTTP_WARMUP").map_or(100, |value| value.parse::<usize>().unwrap());
    assert!(sample_count >= 1000 && warmup >= 100);
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("test PostgreSQL URL");
    let valkey_url = std::env::var("NAZO_TEST_VALKEY_URL")
        .or_else(|_| std::env::var("VALKEY_URL"))
        .expect("test Valkey URL");
    let fixture_bytes = std::fs::read(fixture_path).unwrap();
    let fixture: Value = serde_json::from_slice(&fixture_bytes).unwrap();
    assert_eq!(fixture["version"], 2);
    let fixture_digest = Sha256::digest(&fixture_bytes);
    let cases = prepare_cases(&fixture, &fixture_digest, warmup + sample_count);
    let mut corpus_digest = Sha256::new();
    for case in &cases {
        corpus_digest.update(case.transaction.id.as_bytes());
        corpus_digest.update(case.body.as_bytes());
    }
    let state = infrastructure(&fixture, &database_url, &valkey_url).await;
    let management_token = state
        .settings
        .openid4vc
        .verifier_management_token
        .as_ref()
        .unwrap()
        .clone();
    seed_transactions(&state, &cases).await;
    let mut modules = crate::test_support::persisted_runtime_modules_fixture();
    modules.insert(nazo_runtime_modules::ModuleId::Openid4vpVerifier);
    let facade = Arc::new(
        crate::test_support::facade::builder(
            &state,
            crate::test_support::facade::PersistenceOverrides {
                accepting_modules: Some(modules),
                ..Default::default()
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::from(facade.clone()))
            .configure(nazo_http_actix::configure)
    })
    .workers(1)
    .disable_signals()
    .shutdown_timeout(1)
    .listen(listener)
    .unwrap()
    .run();
    let handle = server.handle();
    let server_task = actix_web::rt::spawn(server);
    let base = format!("http://{address}");
    let client = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let started_at = Utc::now();
    let mut successful = Vec::with_capacity(sample_count);
    let mut samples = Vec::with_capacity(cases.len());
    let mut failures = 0usize;
    for (index, case) in cases.iter().enumerate() {
        let request = client
            .post(format!("{base}/openid4vp/response/{}", case.transaction.id))
            .header("Host", HOST)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(case.body.clone())
            .build()
            .unwrap();
        let start = Instant::now();
        let observed = match reqwest::Client::execute(&client, request).await {
            Ok(response) => {
                let status = response.status().as_u16();
                response
                    .bytes()
                    .await
                    .map(|bytes| (status, bytes))
                    .map_err(|error| error.to_string())
            }
            Err(error) => Err(error.to_string()),
        };
        let elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap();
        let (status, mut error) = match observed {
            Ok((200, _)) => (Some(200), None),
            Ok((status, body)) => (
                Some(status),
                Some(format!(
                    "HTTP {status}: {}",
                    String::from_utf8_lossy(&body)
                        .chars()
                        .take(1024)
                        .collect::<String>()
                )),
            ),
            Err(error) => (None, Some(error)),
        };
        let mut result_status = None;
        if error.is_none() {
            match client
                .get(format!("{base}/openid4vp/result/{}", case.transaction.id))
                .header("Host", HOST)
                .bearer_auth(&management_token)
                .send()
                .await
            {
                Ok(response) => {
                    result_status = Some(response.status().as_u16());
                    if !response.status().is_success() {
                        error = Some("persisted result endpoint failed".into());
                    } else {
                        match response.json::<PresentationResult>().await {
                            Ok(result) if persisted_result_matches(&result, case) => {}
                            Ok(_) => error = Some(
                                "persisted result did not contain the expected authenticated mdoc"
                                    .into(),
                            ),
                            Err(failure) => {
                                error = Some(format!("persisted result decode: {failure}"))
                            }
                        }
                    }
                }
                Err(failure) => error = Some(format!("persisted result transport: {failure}")),
            }
        }
        let success = error.is_none();
        if !success {
            failures += 1;
        }
        if success && index >= warmup {
            successful.push(elapsed_ns);
        }
        samples.push(
            json!({"index": index, "phase": if index < warmup {"warmup"} else {"measured"},
            "elapsed_ns": elapsed_ns, "http_status": status, "result_http_status": result_status,
            "success": success, "error": error}),
        );
        // A broken fixture must not generate thousands of misleading error timings.
        if !success && index < warmup {
            break;
        }
    }
    let replay_rejected = if failures == 0 {
        client
            .post(format!(
                "{base}/openid4vp/response/{}",
                cases[0].transaction.id
            ))
            .header("Host", HOST)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(cases[0].body.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
            == 400
    } else {
        false
    };
    let completed_at = Utc::now();
    handle.stop(true).await;
    server_task.await.unwrap().unwrap();
    let output = json!({
        "scope": "real TCP HTTP/1.1 POST /openid4vp/response/{id}; production single-tenant NazoAuth facade + Actix; Postgres request read + atomic encrypted result persistence; issuer and holder ES256, X.509 path, required operator certificate status snapshot, Final SessionTranscript and DCQL",
        "excluded": ["transaction creation", "wallet signing", "untimed GET persisted-result check", "native host tenant router", "TLS", "HAIP/JWE", "remote MSO status fetching"],
        "credential_status": "absent in authenticated fixture MSO", "certificate_revocation": "Required; explicit synthetic Good operator snapshot for shared leaf and CA",
        "key_storage": "same sealed synthetic keyset loaded into MemorySigningKeyRepository; no signing in timed request",
        "valkey": "production binding connected; this response endpoint has no Valkey roundtrip",
        "issuer_signed_bytes": "complete original encoding spliced unchanged into each independently signed wallet response",
        "panic_strategy": if cfg!(panic = "unwind") { "unwind" } else { "abort" },
        "clock": "std::time::Instant elapsed through complete HTTP response body; endpoint uses live Utc clock",
        "fixture_validity_times": {"issued_at": fixture["issued_at"], "expires_at": fixture["expires_at"]},
        "started_at": started_at, "completed_at": completed_at,
        "variant": std::env::var("NAZO_MDOC_HTTP_VARIANT").unwrap_or_else(|_| "unspecified".into()),
        "revision": std::env::var("NAZO_MDOC_HTTP_REVISION").ok(),
        "fixture_sha256": hex::encode(fixture_digest), "request_corpus_sha256": hex::encode(corpus_digest.finalize()),
        "actix_workers": 1, "client_concurrency": 1, "keep_alive": true, "postgres_pool_size": 4,
        "warmup_requested": warmup, "measurements_requested": sample_count, "failures": failures,
        "replay_rejected": replay_rejected, "valid_performance_comparison": failures == 0 && successful.len() == sample_count && replay_rejected,
        "success_latency": summarize(&successful), "samples": samples,
    });
    std::fs::write(output_path, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    assert_eq!(
        failures, 0,
        "HTTP failures were recorded; no failed response is a successful latency sample"
    );
    assert_eq!(successful.len(), sample_count);
    assert!(replay_rejected, "completed transactions must reject replay");
}
