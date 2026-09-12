use super::*;

pub(crate) async fn parse_backchannel_authentication_form(
    req: &HttpRequest,
    payload: &mut Payload,
) -> Result<BackchannelAuthenticationForm, HttpResponse> {
    if !request_uses_form_urlencoded(req) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request must use application/x-www-form-urlencoded.",
        ));
    }
    let mut body = Vec::with_capacity(16 * 1024);
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA body is invalid.",
            )
        })?;
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return Err(oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "CIBA body is too large.",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let mut form = BackchannelAuthenticationForm::default();
    let mut seen = HashSet::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        let value = value.into_owned();
        let key = key.into_owned();
        if !seen.insert(key.clone()) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA parameters must not repeat.",
            ));
        }
        match key.as_str() {
            "request" => form.request = non_empty(value),
            "scope" => form.scope = non_empty(value),
            "login_hint" => form.login_hint = non_empty(value),
            "id_token_hint" => form.id_token_hint = non_empty(value),
            "login_hint_token" => form.login_hint_token = non_empty(value),
            "binding_message" => form.binding_message = non_empty(value),
            "client_notification_token" => form.client_notification_token = non_empty(value),
            "acr_values" => form.acr_values = non_empty(value),
            "requested_expiry" => {
                form.requested_expiry_seconds = parse_requested_expiry_string(&value)
            }
            "client_id" => form.client_id = non_empty(value),
            "client_secret" => form.client_secret = non_empty(value),
            "client_assertion_type" => form.client_assertion_type = non_empty(value),
            "client_assertion" => form.client_assertion = non_empty(value),
            _ => {}
        }
    }
    Ok(form)
}

fn non_empty(value: String) -> Option<String> {
    let value = value.trim().to_owned();
    (!value.is_empty()).then_some(value)
}
