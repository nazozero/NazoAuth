//! RFC 8628 application request and response data.
use super::oauth_error::OAuthEndpointError;
use http::StatusCode;
use nazo_auth::DeviceAuthorizationPayload;
use serde::Serialize;
pub struct DeviceAuthorizationForm {
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub resources: Vec<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

pub struct PreparedDeviceAuthorization {
    form: DeviceAuthorizationForm,
    has_basic: bool,
}
impl PreparedDeviceAuthorization {
    pub fn form(&self) -> &DeviceAuthorizationForm {
        &self.form
    }
    pub(crate) fn into_parts(self) -> (DeviceAuthorizationForm, bool) {
        (self.form, self.has_basic)
    }
}
pub fn prepare_device_authorization(
    form: DeviceAuthorizationForm,
    has_basic: bool,
) -> Result<PreparedDeviceAuthorization, OAuthEndpointError> {
    let Some(_) = form.client_id.as_deref() else {
        return Err(OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        ));
    };
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
    {
        return Err(OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization request cannot mix client authentication methods.",
        ));
    }
    Ok(PreparedDeviceAuthorization { form, has_basic })
}
#[derive(Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}
pub struct DeviceVerificationData {
    pub user_code: String,
    pub request: Option<DeviceAuthorizationPayload>,
}
