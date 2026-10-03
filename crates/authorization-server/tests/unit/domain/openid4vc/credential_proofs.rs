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
            if let Some(issuer) = issuer { claims["iss"] = issuer; }
            let proof = signed_jwt_proof(Some(&jwk), &key, &claims,
                Some("openid4vci-proof+jwt"), Algorithm::ES256, None);
            assert_eq!(validate_jwt_proof(&validator, proof, &metadata).await.unwrap().len(), 1);
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
            let proof = signed_jwt_proof(Some(&jwk), &key, &claims,
                Some("openid4vci-proof+jwt"), Algorithm::ES256, None);
            assert_eq!(validate_jwt_proof(&validator, proof, &metadata).await,
                Err(ProofError::InvalidSignature));
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
                if let Some(nonce) = nonce { claims["nonce"] = json!(nonce); }
                let (validator, attestation, _) = key_attestation_fixture(claims);
                let proof = signed_jwt_proof(Some(&jwk), &key, &proof_claims,
                    Some("openid4vci-proof+jwt"), Algorithm::ES256, Some(&attestation));
                let result = validate_jwt_proof(&validator, proof, &metadata).await;
                if nonce == Some("expected-nonce") {
                    assert_eq!(result.unwrap()[0].holder_binding, json!({"jwk":jwk}));
                } else {
                    assert_eq!(result, Err(ProofError::InvalidKeyAttestation));
                }
                let other = signed_jwt_proof(Some(&other_jwk), &other_key, &proof_claims,
                    Some("openid4vci-proof+jwt"), Algorithm::ES256, Some(&attestation));
                assert_eq!(validate_jwt_proof(&validator, other, &metadata).await,
                    Err(ProofError::InvalidKeyAttestation));
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
    for context in [KeyAttestationContext::AttestationProof, KeyAttestationContext::JwtProof] {
        validate_key_attestation(&validator, &encoded, "expected-nonce", &allowed, now, context)
            .expect("advertised ES256 verifies");
        assert_eq!(validate_key_attestation(&validator, &encoded, "expected-nonce", &unsupported, now, context),
            Err(ProofError::InvalidKeyAttestation));
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
                "attestation".to_owned(), vec![json!(encoded); count],
            )]));
            let result = validator.validate(&proofs, "wallet-client", "https://issuer.example",
                "expected-nonce", &metadata).await;
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
