use super::*;

#[allow(clippy::too_many_arguments)]
fn metadata<'a>(
    client_type: &'a str,
    redirect_uris: &'a [String],
    scopes: &'a [String],
    allowed_audiences: &'a [String],
    grant_types: &'a [String],
    token_endpoint_auth_method: &'a str,
    jwks: Option<&'a Value>,
    mtls_binding: Option<&'a ClientMtlsMetadata>,
) -> ClientMetadata<'a> {
    ClientMetadata {
        client_type,
        redirect_uris,
        post_logout_redirect_uris: &[],
        scopes,
        allowed_audiences,
        grant_types,
        token_endpoint_auth_method,
        backchannel_logout_uri: None,
        jwks,
        allow_jwks_without_kid: false,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        mtls_binding,
    }
}

#[test]
fn client_metadata_rejects_removed_or_unsafe_grants() {
    let invalid_type = validate_client_metadata(metadata(
        "native",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));
    assert!(
        invalid_type
            .expect_err("unknown client_type must fail closed")
            .to_string()
            .contains("客户端类型无效")
    );

    let result = validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["password".to_owned()],
        "none",
        None,
        None,
    ));

    let error = result.expect_err("password grant must be rejected");
    assert!(
        error.to_string().contains("不支持的 grant_type: password"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_metadata_rejects_unsupported_auth_and_unsafe_grant_combinations() {
    let invalid_auth = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_jwt",
        None,
        None,
    ));
    assert!(
        invalid_auth
            .expect_err("unsupported token endpoint auth method must fail")
            .to_string()
            .contains("客户端认证方式无效")
    );

    let public_client_credentials = validate_client_metadata(metadata(
        "public",
        &[],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["client_credentials".to_owned()],
        "none",
        None,
        None,
    ));
    assert!(
        public_client_credentials
            .expect_err("public clients must not use client_credentials")
            .to_string()
            .contains("public 客户端不能使用 client_credentials 授权类型")
    );

    let client_credentials_openid = validate_client_metadata(metadata(
        "confidential",
        &[],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["client_credentials".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    assert!(
        client_credentials_openid
            .expect_err("client_credentials must not issue OIDC user scopes")
            .to_string()
            .contains("client_credentials 客户端不能申请 openid 作用域")
    );

    let refresh_without_authorization_code = validate_client_metadata(metadata(
        "confidential",
        &[],
        &["accounts".to_owned()],
        &["resource://default".to_owned()],
        &["refresh_token".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    assert!(
        refresh_without_authorization_code
            .expect_err("refresh_token grant must be paired with authorization_code")
            .to_string()
            .contains("refresh_token 授权类型必须与 authorization_code 一起启用")
    );

    let auth_code_without_redirect = validate_client_metadata(metadata(
        "confidential",
        &[],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    assert!(
        auth_code_without_redirect
            .expect_err("authorization_code clients must register redirect_uri")
            .to_string()
            .contains("authorization_code 客户端必须注册 redirect_uri")
    );
}

#[test]
fn client_metadata_rejects_non_loopback_http_redirect_uri() {
    let result = validate_client_metadata(metadata(
        "public",
        &["http://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));

    let error = result.expect_err("non-loopback http redirect_uri must fail closed");
    assert!(
        error
            .to_string()
            .contains("http redirect_uri 只允许 public native client 使用 loopback 地址"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_metadata_requires_refresh_grant_for_offline_access() {
    let result = validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned(), "offline_access".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));

    let error = result.expect_err("offline_access without refresh_token grant must fail");
    assert!(
        error
            .to_string()
            .contains("offline_access 作用域必须与 refresh_token 授权类型一起启用"),
        "unexpected error: {error}"
    );

    validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned(), "offline_access".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned(), "refresh_token".to_owned()],
        "none",
        None,
        None,
    ))
    .expect("offline_access is valid when refresh_token grant is enabled");
}

#[test]
fn client_metadata_requires_public_jwks_for_private_key_jwt() {
    let jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": "key-1"
        }]
    });

    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        None,
        None,
    ));
    let error = result.expect_err("private_key_jwt without registered jwks must fail");
    assert!(
        error
            .to_string()
            .contains("private_key_jwt 客户端必须配置 jwks"),
        "unexpected error: {error}"
    );

    let encryption_only_jwks = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "enc-key"
        }]
    });
    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        Some(&encryption_only_jwks),
        None,
    ));
    let error =
        result.expect_err("private_key_jwt must still require a signing key in registered jwks");
    assert!(
        error
            .to_string()
            .contains("private_key_jwt 客户端必须配置签名 jwks"),
        "unexpected error: {error}"
    );

    validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        Some(&jwks),
        None,
    ))
    .expect("private_key_jwt with a supported public jwks should be accepted");

    let public_private_key_jwt = validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "private_key_jwt",
        Some(&jwks),
        None,
    ));
    assert!(
        public_private_key_jwt
            .expect_err("private_key_jwt must not be available to public clients")
            .to_string()
            .contains("public 客户端只能使用 none 认证方式")
    );
}

#[test]
fn client_metadata_rejects_public_client_secret_and_confidential_none() {
    let public_with_secret = validate_client_metadata(metadata(
        "public",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        None,
    ));
    let error =
        public_with_secret.expect_err("public clients must not use confidential client auth");
    assert!(
        error
            .to_string()
            .contains("public 客户端只能使用 none 认证方式"),
        "unexpected error: {error}"
    );

    let confidential_without_auth = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "none",
        None,
        None,
    ));
    let error = confidential_without_auth
        .expect_err("confidential clients must authenticate at token endpoint");
    assert!(
        error
            .to_string()
            .contains("confidential 客户端必须使用机密认证方式"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_metadata_rejects_backchannel_logout_uri_with_fragment_or_insecure_host() {
    let redirect_uris = ["https://client.example/callback".to_owned()];
    let scopes = ["openid".to_owned()];
    let audiences = ["resource://default".to_owned()];
    let grants = ["authorization_code".to_owned()];
    let mut fragment_metadata = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        None,
        None,
    );
    fragment_metadata.backchannel_logout_uri = Some("https://client.example/backchannel#fragment");

    let error = validate_client_metadata(fragment_metadata)
        .expect_err("backchannel logout URI must reject fragments per OIDC logout security");
    assert!(
        error
            .to_string()
            .contains("backchannel_logout_uri 不能包含 fragment"),
        "unexpected error: {error}"
    );

    let mut insecure_metadata = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        None,
        None,
    );
    insecure_metadata.backchannel_logout_uri = Some("http://client.example/backchannel");

    let error = validate_client_metadata(insecure_metadata)
        .expect_err("backchannel logout URI must reject non-loopback http");
    assert!(
        error
            .to_string()
            .contains("backchannel_logout_uri 必须使用 https 或 loopback http"),
        "unexpected error: {error}"
    );

    for uri in [
        "http://localhost/backchannel",
        "http://127.0.0.1:8080/backchannel",
        "http://app.localhost/backchannel",
    ] {
        let mut loopback_metadata = metadata(
            "confidential",
            &redirect_uris,
            &scopes,
            &audiences,
            &grants,
            "client_secret_basic",
            None,
            None,
        );
        loopback_metadata.backchannel_logout_uri = Some(uri);
        validate_client_metadata(loopback_metadata)
            .expect("OIDC backchannel logout may use loopback HTTP endpoints for local clients");
    }
}

#[test]
fn client_metadata_validates_optional_jwks_for_all_auth_methods() {
    let private_jwk = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "d": URL_SAFE_NO_PAD.encode([8u8; 32]),
            "kid": "key-1"
        }]
    });

    let result = validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        Some(&private_jwk),
        None,
    ));
    let error = result.expect_err("registered jwks must not contain private key material");
    assert!(
        error.to_string().contains("jwks 不能包含私钥材料"),
        "unexpected error: {error}"
    );

    validate_client_metadata(metadata(
        "confidential",
        &["https://client.example/callback".to_owned()],
        &["openid".to_owned()],
        &["resource://default".to_owned()],
        &["authorization_code".to_owned()],
        "client_secret_basic",
        None,
        None,
    ))
    .expect("client_secret_basic may omit jwks");
}

#[test]
fn client_metadata_validates_introspection_jwe_metadata() {
    let redirect_uris = ["https://client.example/callback".to_owned()];
    let scopes = ["openid".to_owned()];
    let audiences = ["resource://default".to_owned()];
    let grants = ["authorization_code".to_owned()];
    let encryption_jwks = json!({
        "keys": [{
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode([0x91u8; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01u8, 0x00, 0x01]),
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "kid": "enc-key"
        }]
    });

    let mut missing_enc = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    missing_enc.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    let error =
        validate_client_metadata(missing_enc).expect_err("JWE alg without enc must fail closed");
    assert!(
        error
            .to_string()
            .contains("introspection_encrypted_response_alg 必须同时配置"),
        "unexpected error: {error}"
    );

    let mut missing_alg = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    missing_alg.introspection_encrypted_response_enc = Some("A256GCM");
    let error =
        validate_client_metadata(missing_alg).expect_err("JWE enc without alg must fail closed");
    assert!(
        error
            .to_string()
            .contains("introspection_encrypted_response_enc 不能在未设置"),
        "unexpected error: {error}"
    );

    let mut unsupported_enc = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    unsupported_enc.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    unsupported_enc.introspection_encrypted_response_enc = Some("A128CBC-HS256");
    let error = validate_client_metadata(unsupported_enc)
        .expect_err("unsupported JWE enc must fail closed");
    assert!(
        error
            .to_string()
            .contains("introspection_encrypted_response_enc 必须是 A256GCM"),
        "unexpected error: {error}"
    );

    let signing_jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode([7u8; 32]),
            "alg": "EdDSA",
            "use": "sig",
            "kid": "sig-key"
        }]
    });
    let mut missing_encryption_key = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&signing_jwks),
        None,
    );
    missing_encryption_key.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    missing_encryption_key.introspection_encrypted_response_enc = Some("A256GCM");
    let error = validate_client_metadata(missing_encryption_key)
        .expect_err("JWE response requires a matching encryption JWK");
    assert!(
        error.to_string().contains("必须配置匹配的 jwks 加密公钥"),
        "unexpected error: {error}"
    );

    let mut valid = metadata(
        "confidential",
        &redirect_uris,
        &scopes,
        &audiences,
        &grants,
        "client_secret_basic",
        Some(&encryption_jwks),
        None,
    );
    valid.introspection_encrypted_response_alg = Some("RSA-OAEP-256");
    valid.introspection_encrypted_response_enc = Some("A256GCM");
    validate_client_metadata(valid)
        .expect("supported JWE metadata with a matching encryption JWK should be accepted");
}
