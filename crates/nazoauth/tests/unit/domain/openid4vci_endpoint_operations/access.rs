use super::*;

#[tokio::test]
async fn access_rejects_signed_token_for_different_tenant_before_revocation_lookup() {
    let issuer = operations(true).await;
    let other_tenant = Uuid::from_u128(0x2222);
    assert_ne!(other_tenant, issuer.tenant_id);
    let subject = Uuid::from_u128(0x3333);
    let subject_string = subject.to_string();
    let audiences = [issuer.issuer.clone()];
    let authorization_details = Value::Array(Vec::new());
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: other_tenant,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: &audiences,
            scopes: &[],
            authorization_details: &authorization_details,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token");

    let mut context = request_context();
    context.bearer_token = issued.token;
    let error = issuer
        .access(&context)
        .await
        .expect_err("a token from another tenant must be rejected before state access");
    assert_error(
        error,
        401,
        "invalid_token",
        "Access token tenant does not match this credential issuer.",
    );
}

#[tokio::test]
async fn access_rejects_signed_token_with_another_audience_before_state_access() {
    let issuer = operations(true).await;
    let subject = Uuid::from_u128(0x4444);
    let subject_string = subject.to_string();
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: issuer.tenant_id,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: &["https://another.example".to_owned()],
            scopes: &[],
            authorization_details: &Value::Array(Vec::new()),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token");

    let mut context = request_context();
    context.bearer_token = issued.token;
    let error = issuer
        .access(&context)
        .await
        .expect_err("token for another audience must be rejected");
    assert_error(
        error,
        401,
        "invalid_token",
        "Access token is not intended for this credential issuer.",
    );
}

#[tokio::test]
async fn access_fails_closed_when_revocation_state_is_unavailable() {
    let issuer = operations(true).await;
    let subject = Uuid::from_u128(0x5555);
    let subject_string = subject.to_string();
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: issuer.tenant_id,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: std::slice::from_ref(&issuer.issuer),
            scopes: &[],
            authorization_details: &Value::Array(Vec::new()),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token");

    let mut context = request_context();
    context.bearer_token = issued.token;
    let error = issuer
        .access(&context)
        .await
        .expect_err("unavailable revocation state must fail closed");
    assert_error(error, 401, "invalid_token", "Access token is revoked.");
}
