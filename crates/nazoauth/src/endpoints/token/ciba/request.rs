use super::*;

pub async fn parse_backchannel_authentication_form<F>(
    req: &HttpRequest,
    body: F,
) -> Result<BackchannelAuthenticationForm, HttpResponse>
where
    F: std::future::Future<Output = Result<bytes::Bytes, HttpResponse>>,
{
    if !request_uses_form_urlencoded(req) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA request must use application/x-www-form-urlencoded.",
        ));
    }
    let body = body.await?;
    if body.len() > 16 * 1024 {
        return Err(oauth_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request",
            "CIBA body is too large.",
        ));
    }
    let mut form = BackchannelAuthenticationForm::default();
    let mut seen = HashSet::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        if matches!(
            key.as_ref(),
            "scope"
                | "login_hint"
                | "id_token_hint"
                | "login_hint_token"
                | "binding_message"
                | "acr_values"
                | "client_notification_token"
                | "requested_expiry"
        ) {
            form.authentication_parameters_present = true;
        }
        match key.as_ref() {
            "request" => form.request = Some(trim_value(value.into_owned())),
            "scope" => form.scope = non_empty(value.into_owned()),
            "login_hint" => form.login_hint = non_empty(value.into_owned()),
            "id_token_hint" => form.id_token_hint = non_empty(value.into_owned()),
            "login_hint_token" => form.login_hint_token = non_empty(value.into_owned()),
            "binding_message" => form.binding_message = non_empty(value.into_owned()),
            "client_notification_token" => {
                form.client_notification_token = non_empty(value.into_owned())
            }
            "acr_values" => form.acr_values = non_empty(value.into_owned()),
            "requested_expiry" => {
                form.requested_expiry_seconds = parse_requested_expiry_string(&value)
            }
            "client_id" => form.client_id = non_empty(value.into_owned()),
            "client_secret" => {
                form.client_secret = (!value.is_empty()).then(|| value.into_owned());
            }
            "client_assertion_type" => form.client_assertion_type = non_empty(value.into_owned()),
            "client_assertion" => form.client_assertion = non_empty(value.into_owned()),
            _ => {}
        }
        if !seen.insert(key) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA parameters must not repeat.",
            ));
        }
    }
    if form.request.is_some() && form.has_outer_authentication_parameters() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "CIBA signed requests must not include outer authentication parameters.",
        ));
    }
    Ok(form)
}

pub fn non_empty(value: String) -> Option<String> {
    let value = trim_value(value);
    (!value.is_empty()).then_some(value)
}

pub fn trim_value(mut value: String) -> String {
    value.truncate(value.trim_end().len());
    let leading_whitespace = value.len() - value.trim_start().len();
    value.drain(..leading_whitespace);
    value
}
