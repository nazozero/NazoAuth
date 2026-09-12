//! Framework-neutral CIBA creation and authorization views.
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
#[derive(Default)]
pub struct BackchannelAuthenticationForm {
    pub request: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint_token: Option<String>,
    pub binding_message: Option<String>,
    pub acr_values: Option<String>,
    pub requested_expiry_seconds: Option<u64>,
    pub client_notification_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Deserialize)]
pub struct CibaAuthenticationRequestClaims {
    pub iss: Option<String>,
    pub aud: Option<Value>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint_token: Option<String>,
    pub binding_message: Option<String>,
    pub acr_values: Option<String>,
    pub requested_expiry: Option<Value>,
    pub client_notification_token: Option<String>,
}

#[derive(Debug)]
pub struct CibaRequestObjectReplay {
    pub jti: String,
    pub ttl_seconds: u64,
}

#[derive(Deserialize)]
pub struct UnverifiedCibaAuthenticationRequestClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
}

#[derive(serde::Serialize)]
pub struct CibaAuthorizationRequestView {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub binding_message: Option<String>,
    pub interval_seconds: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct PreparedCibaCreation {
    form: BackchannelAuthenticationForm,
}
impl PreparedCibaCreation {
    pub(crate) fn new(form: BackchannelAuthenticationForm) -> Self {
        Self { form }
    }
    pub fn form(&self) -> &BackchannelAuthenticationForm {
        &self.form
    }
    pub(crate) fn into_form(self) -> BackchannelAuthenticationForm {
        self.form
    }
}
#[derive(serde::Serialize)]
pub struct CibaCreationResponse {
    pub auth_req_id: String,
    pub expires_in: u64,
    pub interval: u64,
}
