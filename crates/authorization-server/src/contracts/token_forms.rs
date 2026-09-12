pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub device_code: Option<String>,
    pub auth_req_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub device_secret: Option<String>,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub assertion: Option<String>,
    pub requested_token_type: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub audiences: Vec<String>,
    pub has_audience_param: bool,
}

pub struct TokenOnlyForm {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

pub struct PreAuthorizedTokenParameters {
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
    pub invalid: bool,
}

pub struct ParsedTokenForm {
    pub form: TokenForm,
    pub pre_authorized: PreAuthorizedTokenParameters,
}

#[derive(Debug)]
pub enum TokenFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    InvalidResourceParameter,
    MissingGrantType,
}

#[derive(Debug)]
pub enum TokenManagementFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    MissingToken,
}
