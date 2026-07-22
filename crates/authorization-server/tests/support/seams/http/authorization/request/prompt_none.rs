pub(super) async fn user_grant_covers_requested_scopes(
    state: &crate::domain::TestInfrastructure,
    user_id: Uuid,
    client_id: Uuid,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
) -> Result<bool, HttpResponse> {
    let dependencies = crate::http::authorization::TestAuthorizationDependencies::new(state);
    user_grant_covers_requested_scopes_with_context(
        &dependencies.context(),
        user_id,
        client_id,
        requested_scopes,
        requested_resource_indicators,
        requested_authorization_details,
    )
    .await
}

pub(super) fn stored_grant_covers_requested_authorization(
    stored_scopes: &Value,
    stored_resource_indicators: &Value,
    stored_authorization_details: &Value,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
) -> bool {
    nazo_auth::stored_grant_covers_requested_authorization(
        &nazo_auth::StoredAuthorizationGrant {
            scopes: stored_scopes.clone(),
            resource_indicators: stored_resource_indicators.clone(),
            authorization_details: stored_authorization_details.clone(),
        },
        requested_scopes,
        requested_resource_indicators,
        requested_authorization_details,
    )
}

pub(super) async fn issue_authorization_code_without_interaction(
    state: &crate::domain::TestInfrastructure,
    req: &HttpRequest,
    payload: ConsentPayload,
) -> HttpResponse {
    let dependencies = crate::http::authorization::TestAuthorizationDependencies::new(state);
    issue_authorization_code_without_interaction_with_context(&dependencies.context(), req, payload)
        .await
}
