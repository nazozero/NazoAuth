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
        mtls_binding,
    }
}

#[test]
fn client_metadata_rejects_removed_or_unsafe_grants() {
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
