//! RFC 7591 dynamic client registration endpoint.

use crate::http::{admin::CreateClientRequest, prelude::*};

#[derive(Debug, Default, Deserialize)]
pub(crate) struct DynamicClientRegistrationRequest {
    #[serde(default)]
    pub(crate) redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) response_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) application_type: Option<String>,
    #[serde(default)]
    pub(crate) client_name: Option<String>,
    #[serde(default)]
    pub(crate) scope: Option<String>,
    #[serde(default)]
    pub(crate) token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub(crate) subject_type: Option<String>,
    #[serde(default)]
    pub(crate) sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub(crate) post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub(crate) backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub(crate) backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub(crate) dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    #[serde(default)]
    pub(crate) tls_client_auth_san_email: Vec<String>,
    #[serde(default)]
    pub(crate) jwks_uri: Option<String>,
    #[serde(default)]
    pub(crate) jwks: Option<Value>,
    #[serde(default)]
    pub(crate) software_statement: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct DynamicRegistrationDefaults<'a> {
    pub(crate) default_audience: &'a str,
}

#[derive(Debug)]
pub(crate) struct PreparedDynamicClientRegistration {
    pub(crate) client_name: String,
    pub(crate) client_type: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) post_logout_redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_audiences: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) response_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
    pub(crate) subject_type: Option<String>,
    pub(crate) sector_identifier_uri: Option<String>,
    pub(crate) require_dpop_bound_tokens: bool,
    pub(crate) backchannel_logout_uri: Option<String>,
    pub(crate) backchannel_logout_session_required: bool,
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    pub(crate) tls_client_auth_san_email: Vec<String>,
    pub(crate) jwks: Option<Value>,
}

#[derive(Debug)]
pub(crate) struct DynamicRegistrationError {
    error: &'static str,
    description: String,
}

pub(crate) async fn dynamic_client_registration(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<DynamicClientRegistrationRequest>,
) -> HttpResponse {
    if !state.settings.enable_dynamic_client_registration {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if !initial_access_token_authorized(
        req.headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        state
            .settings
            .dynamic_client_registration_initial_access_token
            .as_deref(),
    ) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Initial access token is missing or invalid.",
        );
    }

    let prepared = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationDefaults {
            default_audience: &state.settings.default_audience,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let request = prepared.into_create_client_request();
    match crate::http::admin::insert_client_row(&state, request).await {
        Ok((client, issued_secret)) => {
            let mut body = dynamic_registration_response(&client, &response_types, issued_secret);
            body["client_id_issued_at"] = json!(Utc::now().timestamp());
            json_response_status(StatusCode::CREATED, body)
        }
        Err(crate::http::admin::InsertClientError::InvalidRequest(message)) => {
            dynamic_registration_error_response(map_insert_error(message))
        }
        Err(crate::http::admin::InsertClientError::Server(message)) => {
            tracing::warn!(%message, "failed to dynamically register oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Dynamic client registration failed.",
            )
        }
    }
}

pub(crate) fn prepare_dynamic_client_registration(
    request: DynamicClientRegistrationRequest,
    defaults: DynamicRegistrationDefaults<'_>,
) -> Result<PreparedDynamicClientRegistration, DynamicRegistrationError> {
    if request.software_statement.is_some() {
        return Err(DynamicRegistrationError::new(
            "invalid_software_statement",
            "software_statement is not supported by this registration endpoint.",
        ));
    }
    if request.jwks_uri.is_some() && request.jwks.is_some() {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "jwks_uri and jwks must not both be present.",
        ));
    }
    if request.jwks_uri.is_some() {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "jwks_uri is not supported; register jwks by value.",
        ));
    }
    if let Some(application_type) = request.application_type.as_deref()
        && !matches!(application_type, "web" | "native")
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "application_type must be web or native.",
        ));
    }

    let grant_types = request
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_owned()]);
    let response_types = match request.response_types {
        Some(values) if values.is_empty() => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "response_types must not be empty.",
            ));
        }
        Some(values) => values,
        None if grant_types
            .iter()
            .any(|grant| grant == "authorization_code") =>
        {
            vec!["code".to_owned()]
        }
        None => Vec::new(),
    };
    validate_response_type_relationship(&grant_types, &response_types)?;

    let token_endpoint_auth_method = request
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".to_owned());
    let client_type = if token_endpoint_auth_method == "none" {
        "public".to_owned()
    } else {
        "confidential".to_owned()
    };
    let scopes = request
        .scope
        .as_deref()
        .map(parse_scope)
        .unwrap_or_else(|| {
            if grant_types
                .iter()
                .any(|grant| grant == "authorization_code")
            {
                vec!["openid".to_owned()]
            } else {
                Vec::new()
            }
        });
    let client_name = request
        .client_name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Dynamic OAuth Client".to_owned());

    Ok(PreparedDynamicClientRegistration {
        client_name,
        client_type,
        redirect_uris: request.redirect_uris.unwrap_or_default(),
        post_logout_redirect_uris: request.post_logout_redirect_uris,
        scopes,
        allowed_audiences: vec![defaults.default_audience.to_owned()],
        grant_types,
        response_types,
        token_endpoint_auth_method,
        subject_type: request.subject_type,
        sector_identifier_uri: request.sector_identifier_uri,
        require_dpop_bound_tokens: request.dpop_bound_access_tokens,
        backchannel_logout_uri: request.backchannel_logout_uri,
        backchannel_logout_session_required: request
            .backchannel_logout_session_required
            .unwrap_or(true),
        tls_client_auth_subject_dn: request.tls_client_auth_subject_dn,
        tls_client_auth_cert_sha256: request.tls_client_auth_cert_sha256,
        tls_client_auth_san_dns: request.tls_client_auth_san_dns,
        tls_client_auth_san_uri: request.tls_client_auth_san_uri,
        tls_client_auth_san_ip: request.tls_client_auth_san_ip,
        tls_client_auth_san_email: request.tls_client_auth_san_email,
        jwks: request.jwks,
    })
}

pub(crate) fn initial_access_token_authorized(
    authorization_header: Option<&str>,
    expected_token: Option<&str>,
) -> bool {
    let Some(expected_token) = expected_token else {
        return true;
    };
    let Some(actual) = authorization_header
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    constant_time_eq(actual.as_bytes(), expected_token.as_bytes())
}

impl PreparedDynamicClientRegistration {
    fn to_create_client_request(&self) -> CreateClientRequest {
        CreateClientRequest {
            client_name: self.client_name.clone(),
            client_type: self.client_type.clone(),
            redirect_uris: self.redirect_uris.clone(),
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            scopes: self.scopes.clone(),
            allowed_audiences: self.allowed_audiences.clone(),
            grant_types: self.grant_types.clone(),
            token_endpoint_auth_method: self.token_endpoint_auth_method.clone(),
            subject_type: self.subject_type.clone(),
            sector_identifier_uri: self.sector_identifier_uri.clone(),
            require_dpop_bound_tokens: self.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            allow_authorization_code_without_pkce: self.client_type == "confidential"
                && !self.require_dpop_bound_tokens
                && matches!(
                    self.token_endpoint_auth_method.as_str(),
                    "client_secret_basic" | "client_secret_post"
                ),
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            tls_client_auth_subject_dn: self.tls_client_auth_subject_dn.clone(),
            tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256.clone(),
            tls_client_auth_san_dns: self.tls_client_auth_san_dns.clone(),
            tls_client_auth_san_uri: self.tls_client_auth_san_uri.clone(),
            tls_client_auth_san_ip: self.tls_client_auth_san_ip.clone(),
            tls_client_auth_san_email: self.tls_client_auth_san_email.clone(),
            jwks: self.jwks.clone(),
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            allow_jwks_without_kid: true,
        }
    }

    fn into_create_client_request(self) -> CreateClientRequest {
        self.to_create_client_request()
    }
}

impl DynamicRegistrationError {
    fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new("invalid_client_metadata", description)
    }
}

fn validate_response_type_relationship(
    grant_types: &[String],
    response_types: &[String],
) -> Result<(), DynamicRegistrationError> {
    for response_type in response_types {
        if response_type != "code" {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "only code response type is supported.",
            ));
        }
    }
    let has_code_grant = grant_types
        .iter()
        .any(|grant| grant == "authorization_code");
    let has_code_response = response_types.iter().any(|response| response == "code");
    if has_code_grant != has_code_response {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "authorization_code grant requires code response type.",
        ));
    }
    Ok(())
}

fn map_insert_error(message: String) -> DynamicRegistrationError {
    let error = if message.contains("redirect_uri") {
        "invalid_redirect_uri"
    } else {
        "invalid_client_metadata"
    };
    DynamicRegistrationError::new(error, message)
}

fn dynamic_registration_error_response(error: DynamicRegistrationError) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, error.error, &error.description)
}

fn dynamic_registration_response(
    client: &ClientRow,
    response_types: &[String],
    issued_secret: Option<String>,
) -> Value {
    let mut body = json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": json_array_to_strings(&client.redirect_uris),
        "grant_types": json_array_to_strings(&client.grant_types),
        "response_types": response_types,
        "scope": json_array_to_strings(&client.scopes).join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "subject_type": client.subject_type,
    });
    if let Some(jwks) = &client.jwks {
        body["jwks"] = jwks.clone();
    }
    if let Some(secret) = issued_secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    body
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/dynamic_client_registration.rs"]
mod tests;
