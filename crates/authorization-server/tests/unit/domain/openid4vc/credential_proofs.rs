use super::*;

#[test]
fn credential_proof_requires_scalar_audience_and_matching_present_issuer() {
    futures_executor::block_on(async {
        let (jwk, key) = es256_test_key(71);
        let validator = Openid4vcProofValidator::new(json!({"keys": []})).unwrap();
        let metadata = proof_metadata(None);
        let base = json!({
            "aud": "https://issuer.example", "nonce": "expected-nonce",
            "iat": Utc::now().timestamp(),
        });
        for issuer in [None, Some(json!("wallet-client"))] {
            let mut claims = base.clone();
            if let Some(issuer) = issuer {
                claims["iss"] = issuer;
            }
            let proof = signed_jwt_proof(
                Some(&jwk),
                &key,
                &claims,
                Some("openid4vci-proof+jwt"),
                Algorithm::ES256,
                None,
            );
            assert_eq!(
                validate_jwt_proof(&validator, proof, &metadata)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        for (claim, value) in [
            ("aud", json!(["https://issuer.example"])),
            ("aud", json!(null)),
            ("aud", json!("https://other.example")),
            ("iss", json!("other-wallet")),
            ("iss", json!(42)),
            ("iss", json!(null)),
        ] {
            let mut claims = base.clone();
            claims[claim] = value;
            let proof = signed_jwt_proof(
                Some(&jwk),
                &key,
                &claims,
                Some("openid4vci-proof+jwt"),
                Algorithm::ES256,
                None,
            );
            assert_eq!(
                validate_jwt_proof(&validator, proof, &metadata).await,
                Err(ProofError::InvalidSignature)
            );
        }
    })
}

#[test]
fn credential_proof_binds_optional_attestation_and_requires_its_nonce() {
    futures_executor::block_on(async {
        let now = Utc::now();
        let (jwk, key) = es256_test_key(73);
        let (other_jwk, other_key) = es256_test_key(79);
        let proof_claims = json!({"aud":"https://issuer.example",
            "nonce":"expected-nonce", "iat":now.timestamp()});
        for required in [None, Some(std::collections::BTreeMap::new())] {
            let metadata = proof_metadata(required);
            for nonce in [None, Some("wrong-nonce"), Some("expected-nonce")] {
                let mut claims = json!({"iat":now.timestamp(), "exp":now.timestamp()+300,
                    "attested_keys":[jwk.clone()]});
                if let Some(nonce) = nonce {
                    claims["nonce"] = json!(nonce);
                }
                let (validator, attestation, _) = key_attestation_fixture(claims);
                let proof = signed_jwt_proof(
                    Some(&jwk),
                    &key,
                    &proof_claims,
                    Some("openid4vci-proof+jwt"),
                    Algorithm::ES256,
                    Some(&attestation),
                );
                let result = validate_jwt_proof(&validator, proof, &metadata).await;
                if nonce == Some("expected-nonce") {
                    assert_eq!(result.unwrap()[0].holder_binding, json!({"jwk":jwk}));
                } else {
                    assert_eq!(result, Err(ProofError::InvalidKeyAttestation));
                }
                let other = signed_jwt_proof(
                    Some(&other_jwk),
                    &other_key,
                    &proof_claims,
                    Some("openid4vci-proof+jwt"),
                    Algorithm::ES256,
                    Some(&attestation),
                );
                assert_eq!(
                    validate_jwt_proof(&validator, other, &metadata).await,
                    Err(ProofError::InvalidKeyAttestation)
                );
            }
        }
    })
}

#[test]
fn credential_attestation_algorithm_obeys_selected_configuration_for_both_contexts() {
    let now = Utc::now();
    let (validator, encoded, allowed) = key_attestation_fixture(json!({
        "iat":now.timestamp(), "exp":now.timestamp()+300,
        "nonce":"expected-nonce", "attested_keys":[es256_test_key(83).0],
    }));
    let unsupported = nazo_openid4vci::ProofTypeMetadata {
        proof_signing_alg_values_supported: vec!["EdDSA".to_owned()],
        key_attestations_required: None,
    };
    for context in [
        KeyAttestationContext::AttestationProof,
        KeyAttestationContext::JwtProof,
    ] {
        validate_key_attestation(
            &validator,
            &encoded,
            "expected-nonce",
            &allowed,
            now,
            context,
        )
        .expect("advertised ES256 verifies");
        assert_eq!(
            validate_key_attestation(
                &validator,
                &encoded,
                "expected-nonce",
                &unsupported,
                now,
                context
            ),
            Err(ProofError::InvalidKeyAttestation)
        );
    }
}

#[test]
fn credential_attestation_is_one_jwt_with_multiple_attested_keys() {
    futures_executor::block_on(async {
        let keys = vec![es256_test_key(89).0, es256_test_key(97).0];
        let (validator, encoded, metadata) = key_attestation_fixture(json!({
            "iat":Utc::now().timestamp(), "nonce":"expected-nonce", "attested_keys":keys,
        }));
        for count in [0, 1, 2] {
            let proofs = Proofs(std::collections::BTreeMap::from([(
                "attestation".to_owned(),
                vec![json!(encoded); count],
            )]));
            let result = validator
                .validate(
                    &proofs,
                    "wallet-client",
                    nazo_openid4vci::CredentialProofOrigin::RegisteredClient,
                    "https://issuer.example",
                    "expected-nonce",
                    &metadata,
                )
                .await;
            if count == 1 {
                let validated = result.expect("one JWT may attest multiple keys");
                assert_eq!(validated.len(), keys.len());
                for (proof, key) in validated.iter().zip(&keys) {
                    assert_eq!(proof.holder_binding, json!({"jwk":key}));
                }
            } else {
                assert_eq!(result, Err(ProofError::InvalidKeyAttestation));
            }
        }
    })
}

#[test]
fn credential_proof_issuer_uses_origin_even_for_a_registered_placeholder_name() {
    futures_executor::block_on(async {
        use nazo_openid4vci::CredentialProofOrigin::{
            AnonymousPreAuthorized, LegacyUnspecified, RegisteredClient,
        };
        let (jwk, key) = es256_test_key(101);
        let validator = Openid4vcProofValidator::new(json!({"keys":[]})).unwrap();
        let metadata = proof_metadata(None);
        for client in ["wallet-client", "pre-authorized-wallet"] {
            for origin in [RegisteredClient, AnonymousPreAuthorized, LegacyUnspecified] {
                for issuer in [None, Some(json!(client)), Some(json!("wrong-client"))] {
                    let mut claims = json!({"aud":"https://issuer.example","nonce":"expected-nonce","iat":Utc::now().timestamp()});
                    if let Some(value) = &issuer {
                        claims["iss"] = value.clone();
                    }
                    let proof = signed_jwt_proof(
                        Some(&jwk),
                        &key,
                        &claims,
                        Some("openid4vci-proof+jwt"),
                        Algorithm::ES256,
                        None,
                    );
                    let proofs = Proofs(std::collections::BTreeMap::from([(
                        "jwt".to_owned(),
                        vec![json!(proof)],
                    )]));
                    let result = validator
                        .validate(
                            &proofs,
                            client,
                            origin,
                            "https://issuer.example",
                            "expected-nonce",
                            &metadata,
                        )
                        .await;
                    if issuer.is_none()
                        || (origin == RegisteredClient
                            && issuer.as_ref().and_then(Value::as_str) == Some(client))
                    {
                        assert_eq!(result.unwrap().len(), 1);
                    } else {
                        assert_eq!(result, Err(ProofError::InvalidSignature));
                    }
                }
            }
        }
    })
}

#[test]
fn anonymous_credential_proof_origin_ignores_same_named_registered_client_trust() {
    use nazo_openid4vci::CredentialProofOrigin::{AnonymousPreAuthorized, RegisteredClient};
    use nazo_persistence::{
        ClientTrustPolicy, Openid4vcTrustPolicyRecord, Openid4vcTrustPolicyStore, RepositoryError,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CurrentClientPolicy {
        tenant_id: uuid::Uuid,
        policy: ClientTrustPolicy,
        lookups: AtomicUsize,
    }

    impl Openid4vcTrustPolicyStore for CurrentClientPolicy {
        fn for_client<'a>(
            &'a self,
            tenant_id: uuid::Uuid,
            client_id: &'a str,
        ) -> futures_util::future::BoxFuture<'a, Result<ClientTrustPolicy, RepositoryError>>
        {
            assert_eq!(tenant_id, self.tenant_id);
            assert_eq!(client_id, "pre-authorized-wallet");
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(self.policy.clone()) })
        }

        fn active_for_origin<'a>(
            &'a self,
            _tenant_id: uuid::Uuid,
            _resource_id: &'a str,
            _wallet_origin: &'a str,
            _expected_digest: &'a str,
        ) -> futures_util::future::BoxFuture<
            'a,
            Result<Option<Openid4vcTrustPolicyRecord>, RepositoryError>,
        > {
            panic!("credential proof validation must only read client trust policy")
        }
    }

    futures_executor::block_on(async {
        let now = Utc::now().timestamp();
        let tenant_id = uuid::Uuid::now_v7();
        let (jwk, key) = es256_test_key(101);
        let attestation_claims = json!({
            "iat": now, "exp": now + 300, "nonce": "expected-nonce",
            "attested_keys": [jwk.clone()],
        });
        let (global, global_attestation, metadata) =
            key_attestation_fixture(attestation_claims.clone());
        let (client, client_attestation, _) =
            key_attestation_fixture_with_seed(attestation_claims, 19);
        let proofs = [&global_attestation, &client_attestation].map(|attestation| {
            let proof = signed_jwt_proof(
                Some(&jwk),
                &key,
                &json!({"aud": "https://issuer.example", "nonce": "expected-nonce", "iat": now}),
                Some("openid4vci-proof+jwt"),
                Algorithm::ES256,
                Some(attestation),
            );
            Proofs(std::collections::BTreeMap::from([(
                "jwt".to_owned(),
                vec![json!(proof)],
            )]))
        });
        let client_policy = Openid4vcTrustPolicyRecord {
            id: uuid::Uuid::now_v7(),
            resource_id: "same-named-client-policy".to_owned(),
            resource_digest: "proof-origin-fixture".to_owned(),
            material: nazo_operator_protocol::Openid4vcTrustPolicy {
                schema: 1,
                client_attestation_issuer: "https://attester.example".to_owned(),
                client_attestation_jwks: json!({"keys": []}),
                key_attestation_jwks: client.key_attestation_jwks.as_ref().clone(),
                credential_trust_anchor_pem: String::new(),
                wallet_authorization_origins: Vec::new(),
            },
        };
        for (policy, registered_acceptance) in [
            (ClientTrustPolicy::Unbound, [true, false]),
            (
                ClientTrustPolicy::Active(Box::new(client_policy)),
                [false, true],
            ),
            (ClientTrustPolicy::BoundInactive, [false, false]),
        ] {
            let repository = Arc::new(CurrentClientPolicy {
                tenant_id,
                policy,
                lookups: AtomicUsize::new(0),
            });
            let validator = global
                .clone()
                .with_trust_policies(repository.clone(), tenant_id);
            for (origin, acceptance, expected_lookups) in [
                (AnonymousPreAuthorized, [true, false], 0),
                (RegisteredClient, registered_acceptance, 2),
            ] {
                for (proofs, accepted) in proofs.iter().zip(acceptance) {
                    let result = validator
                        .validate(
                            proofs,
                            "pre-authorized-wallet",
                            origin,
                            "https://issuer.example",
                            "expected-nonce",
                            &metadata,
                        )
                        .await;
                    if accepted {
                        assert_eq!(result.unwrap().len(), 1);
                    } else {
                        assert_eq!(result, Err(ProofError::InvalidKeyAttestation));
                    }
                }
                assert_eq!(repository.lookups.load(Ordering::SeqCst), expected_lookups);
            }
        }
    });
}

#[test]
fn credential_embedded_attestation_algorithm_is_checked_after_valid_eddsa_outer_proof() {
    futures_executor::block_on(async {
        use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
        let document =
            Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let jwk = json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())});
        let key = EncodingKey::from_ed_der(document.as_ref());
        let now = Utc::now();
        let (validator, attestation, _) = key_attestation_fixture(json!({
            "iat":now.timestamp(),"exp":now.timestamp()+300,"nonce":"expected-nonce","attested_keys":[jwk.clone()],
        }));
        let claims =
            json!({"aud":"https://issuer.example","iat":now.timestamp(),"nonce":"expected-nonce"});
        let allowed = nazo_openid4vci::ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["EdDSA".to_owned(), "ES256".to_owned()],
            key_attestations_required: None,
        };
        let only_outer = nazo_openid4vci::ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["EdDSA".to_owned()],
            key_attestations_required: None,
        };
        let plain = signed_jwt_proof(
            Some(&jwk),
            &key,
            &claims,
            Some("openid4vci-proof+jwt"),
            Algorithm::EdDSA,
            None,
        );
        assert_eq!(
            validate_jwt_proof(&validator, plain, &only_outer)
                .await
                .unwrap()
                .len(),
            1,
            "the outer EdDSA signature and selected algorithm are valid"
        );
        let embedded = signed_jwt_proof(
            Some(&jwk),
            &key,
            &claims,
            Some("openid4vci-proof+jwt"),
            Algorithm::EdDSA,
            Some(&attestation),
        );
        assert_eq!(
            validate_jwt_proof(&validator, embedded.clone(), &allowed)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            validate_jwt_proof(&validator, embedded, &only_outer).await,
            Err(ProofError::InvalidKeyAttestation),
            "only the inner ES256 advertised subset check rejects this request"
        );
    })
}
