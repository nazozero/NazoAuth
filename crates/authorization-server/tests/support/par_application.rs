use super::*;
use app::authorization::par::ParRequestFacts;
use app::contracts::request_facts::DpopRequestFacts;
use app::contracts::token_client_auth::{
    BasicAuthorizationCredentials, TokenClientAuthTransportFacts,
};
use app::token::client_auth::ClientAuthRequestFacts;
use serde_json::json;

fn client(active: bool) -> OAuthClient {
    let mut client = authorization_fixture::client(active);
    client.client_type = "public".into();
    client.token_endpoint_auth_method = "none".into();
    client
}

fn par_fixture(client: Result<Option<OAuthClient>, AuthorizationPortError>) -> Fixture {
    let fixture = Fixture::new(client, Ok(None));
    *fixture.ports.par_rate.lock().unwrap() = Some(Ok(1));
    *fixture.ports.par_write.lock().unwrap() = Some(Ok(()));
    fixture
}
fn params() -> HashMap<String, String> {
    HashMap::from([
        ("client_id".into(), "client-1".into()),
        ("response_type".into(), "code".into()),
        (
            "redirect_uri".into(),
            "https://client.example/callback".into(),
        ),
        ("code_challenge".into(), "a".repeat(43)),
        ("code_challenge_method".into(), "S256".into()),
        ("scope".into(), "openid".into()),
    ])
}
fn transport() -> TokenClientAuthTransportFacts {
    TokenClientAuthTransportFacts::from_parts(
        BasicAuthorizationCredentials::Absent,
        Some("client-1".into()),
        None,
        None,
        None,
    )
}
fn facts() -> ParRequestFacts<'static> {
    ParRequestFacts {
        client_auth: ClientAuthRequestFacts::new("/par", None),
        dpop: DpopRequestFacts {
            method: http::Method::POST,
            path: "/par",
            proof: Ok(None),
            proof_present: false,
        },
        mtls_thumbprint: None,
        attestation: None,
    }
}
#[test]
fn par_persists_bound_request_and_reports_write_failure() {
    block_on(async {
        let fixture = par_fixture(Ok(Some(client(true))));
        let app = fixture.make_application();
        let response = app
            .begin_par("127.0.0.1")
            .await
            .unwrap()
            .prepare_parameters(params(), false, None)
            .unwrap()
            .prepare_client(&transport(), false, false)
            .await
            .unwrap()
            .par(facts(), None)
            .await
            .unwrap();
        {
            let stored = fixture.ports.stored_par.lock().unwrap();
            assert_eq!(stored.len(), 1);
            assert_eq!(response["request_uri"], stored[0].0);
            assert_eq!(response["expires_in"], 90);
            assert_eq!(stored[0].2, 90);
            assert_eq!(stored[0].1.client_id, "client-1");
            assert_eq!(stored[0].1.params, params());
            assert!(stored[0].1.dpop_jkt.is_none());
        }
        *fixture.ports.par_write.lock().unwrap() = Some(Err(AuthorizationPortError::Unavailable));
        let error = app
            .begin_par("127.0.0.1")
            .await
            .unwrap()
            .prepare_parameters(params(), false, None)
            .unwrap()
            .prepare_client(&transport(), false, false)
            .await
            .unwrap()
            .par(facts(), None)
            .await
            .unwrap_err();
        assert_json_error(error, StatusCode::SERVICE_UNAVAILABLE, "server_error");
        assert_eq!(fixture.ports.stored_par.lock().unwrap().len(), 1);
    });
}
#[test]
fn par_client_lookup_and_attestation_errors_do_not_persist() {
    block_on(async {
        for (value, status) in [
            (Ok(None), StatusCode::UNAUTHORIZED),
            (Ok(Some(client(false))), StatusCode::UNAUTHORIZED),
            (
                Err(AuthorizationPortError::Unavailable),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let fixture = par_fixture(value);
            let app = fixture.make_application();
            let error = app
                .begin_par("ip")
                .await
                .unwrap()
                .prepare_parameters(params(), false, None)
                .unwrap()
                .prepare_client(&transport(), false, false)
                .await
                .err()
                .unwrap();
            assert_json_error(
                error,
                status,
                if status == StatusCode::UNAUTHORIZED {
                    "invalid_client"
                } else {
                    "server_error"
                },
            );
            assert!(fixture.ports.stored_par.lock().unwrap().is_empty());
        }
        for registered in [false, true] {
            let mut client = client(true);
            if registered {
                client.token_endpoint_auth_method = "attest_jwt_client_auth".into();
            }
            let fixture = par_fixture(Ok(Some(client)));
            let app = fixture.make_application();
            let mut facts = facts();
            facts.attestation = Some(("invalid-attestation", "proof"));
            let error = app
                .begin_par("ip")
                .await
                .unwrap()
                .prepare_parameters(params(), false, None)
                .unwrap()
                .prepare_client(&transport(), false, true)
                .await
                .unwrap()
                .par(facts, None)
                .await
                .unwrap_err();
            assert_json_error(
                error,
                StatusCode::UNAUTHORIZED,
                "invalid_client_attestation",
            );
            assert!(fixture.ports.stored_par.lock().unwrap().is_empty());
        }
    });
}
#[test]
fn par_parameter_and_rate_errors_fail_before_client_lookup() {
    block_on(async {
        for (key, value, basic) in [
            ("client_secret", "secret", true),
            ("request", "jwt", false),
            ("authorization_details", "[]", false),
        ] {
            let fixture = par_fixture(Ok(Some(client(true))));
            let app = fixture.make_application();
            let mut params = params();
            params.insert(key.into(), value.into());
            let error = app
                .begin_par("ip")
                .await
                .unwrap()
                .prepare_parameters(params, basic, None)
                .err()
                .unwrap();
            assert_json_error(error, StatusCode::BAD_REQUEST, "invalid_request");
            assert_eq!(fixture.ports.calls(), ["rate"]);
        }
        let fixture = par_fixture(Ok(None));
        let app = fixture.make_application();
        assert_json_error(
            app.begin_par("ip")
                .await
                .unwrap()
                .prepare_parameters(HashMap::new(), false, None)
                .err()
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
        *fixture.ports.par_rate.lock().unwrap() = Some(Ok(11));
        assert!(matches!(
            app.begin_par("ip").await,
            Err(OAuthEndpointError::RateLimited {
                retry_after_seconds: 60
            })
        ));
        *fixture.ports.par_rate.lock().unwrap() = Some(Err(AuthorizationPortError::Unavailable));
        assert_json_error(
            app.begin_par("ip").await.err().unwrap(),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        );
    });
}
#[test]
fn par_rejects_invalid_redirect_pkce_and_dpop_before_storage() {
    block_on(async {
        for (key, value, expected) in [
            ("request_uri", "urn:request", "invalid_request_object"),
            ("response_type", "token", "unsupported_response_type"),
            (
                "redirect_uri",
                "https://attacker.example/callback",
                "invalid_request",
            ),
            ("code_challenge_method", "plain", "invalid_request"),
            ("code_challenge", "short", "invalid_request"),
            ("resource", "relative", "invalid_target"),
            ("resource", "https://other.example", "invalid_target"),
            ("dpop_jkt", "invalid", "invalid_request"),
        ] {
            let fixture = par_fixture(Ok(Some(client(true))));
            let app = fixture.make_application();
            let mut params = params();
            params.insert(key.into(), value.into());
            let error = app
                .begin_par("ip")
                .await
                .unwrap()
                .prepare_parameters(params, false, None)
                .unwrap()
                .prepare_client(&transport(), false, false)
                .await
                .unwrap()
                .par(facts(), None)
                .await
                .unwrap_err();
            assert_json_error(error, StatusCode::BAD_REQUEST, expected);
            assert!(fixture.ports.stored_par.lock().unwrap().is_empty());
        }
        let fixture = par_fixture(Ok(Some(client(true))));
        let app = fixture.make_application();
        let mut facts = facts();
        facts.dpop.proof = Err(nazo_auth::DpopError::InvalidProof);
        facts.dpop.proof_present = true;
        let error = app
            .begin_par("ip")
            .await
            .unwrap()
            .prepare_parameters(params(), false, None)
            .unwrap()
            .prepare_client(&transport(), false, false)
            .await
            .unwrap()
            .par(facts, None)
            .await
            .unwrap_err();
        assert!(matches!(error, OAuthEndpointError::Dpop { .. }));
        assert!(fixture.ports.stored_par.lock().unwrap().is_empty());
    });
}

#[test]
fn par_attestation_requires_valid_proof_and_available_single_use_replay_state() {
    use app::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    let key = SigningKey::from_slice(&[9; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let jwk = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap()),"kid":"test-key"});
    let sign = |typ: &str, claims: serde_json::Value| {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({"alg":"ES256","typ":typ,"kid":"test-key"})).unwrap()
            ),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    };
    let now = chrono::Utc::now().timestamp();
    let attestation = sign(
        "oauth-client-attestation+jwt",
        json!({"iss":"https://attester.example","sub":"client-1","exp":now+600,"cnf":{"jwk":jwk}}),
    );
    let validator =
        Openid4vcClientAttestationValidator::new("https://attester.example", json!({"keys":[jwk]}))
            .unwrap();
    block_on(async {
        for case in 0..4 {
            let mut client = client(true);
            client.token_endpoint_auth_method = "attest_jwt_client_auth".into();
            let fixture = par_fixture(Ok(Some(client)));
            *fixture.ports.assertion_replay.lock().unwrap() = Some(match case {
                2 => Ok(false),
                3 => Err(AuthorizationPortError::Unavailable),
                _ => Ok(true),
            });
            let app = fixture.make_application();
            let proof = sign(
                "oauth-client-attestation-pop+jwt",
                json!({"iss":"client-1","aud":fixture.config.issuer,"iat":now,"jti":format!("par-proof-{case}")}),
            );
            let pair = (
                attestation.as_str(),
                if case == 1 {
                    "invalid-proof"
                } else {
                    proof.as_str()
                },
            );
            let mut parameters = params();
            parameters.remove("client_id");
            let mut facts = facts();
            facts.attestation = Some(pair);
            let result = app
                .begin_par("127.0.0.1")
                .await
                .unwrap()
                .prepare_parameters(parameters, false, Some(pair))
                .unwrap()
                .prepare_client(&transport(), false, true)
                .await
                .unwrap()
                .par(facts, Some(&validator))
                .await;
            if case == 0 {
                assert!(result.is_ok());
                assert_eq!(fixture.ports.stored_par.lock().unwrap().len(), 1);
            } else {
                assert_json_error(
                    result.unwrap_err(),
                    if case == 3 {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::UNAUTHORIZED
                    },
                    if case == 3 {
                        "server_error"
                    } else {
                        "invalid_client_attestation"
                    },
                );
                assert!(fixture.ports.stored_par.lock().unwrap().is_empty());
            }
        }
    });
}
