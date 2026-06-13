//! Token 相关表单模型。
// 表单结构在多个 token 子模块之间共享。
use crate::http::prelude::*;

pub(crate) struct TokenForm {
    pub(crate) grant_type: String,
    pub(crate) code: Option<String>,
    pub(crate) redirect_uri: Option<String>,
    pub(crate) code_verifier: Option<String>,
    pub(crate) refresh_token: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion_type: Option<String>,
    pub(crate) client_assertion: Option<String>,
    pub(crate) audiences: Vec<String>,
}

pub(crate) struct TokenOnlyForm {
    pub(crate) token: String,
    pub(crate) token_type_hint: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion_type: Option<String>,
    pub(crate) client_assertion: Option<String>,
}

#[derive(Debug)]
pub(crate) enum TokenFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    InvalidResourceParameter,
    MissingGrantType,
}

#[derive(Debug)]
pub(crate) enum TokenManagementFormError {
    InvalidContentType,
    InvalidEncoding,
    DuplicateParameter,
    MissingToken,
}

pub(crate) fn token_management_oauth_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    oauth_token_error(status, error, description, false)
}

pub(crate) fn token_management_form_error(error: TokenManagementFormError) -> HttpResponse {
    match error {
        TokenManagementFormError::InvalidContentType => token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token management 请求必须使用 application/x-www-form-urlencoded.",
        ),
        TokenManagementFormError::InvalidEncoding => token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token management 请求体必须使用 UTF-8 编码.",
        ),
        TokenManagementFormError::DuplicateParameter => token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        ),
        TokenManagementFormError::MissingToken => {
            token_management_oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "缺少 token.")
        }
    }
}

pub(crate) fn parse_token_form(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<TokenForm, TokenFormError> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(TokenFormError::InvalidContentType);
    }

    let raw = std::str::from_utf8(body).map_err(|_| TokenFormError::InvalidEncoding)?;
    let mut seen = std::collections::HashSet::new();
    let mut resource_values = std::collections::HashSet::new();
    let mut form = TokenForm {
        grant_type: String::new(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        audiences: Vec::new(),
    };

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        if !matches!(
            key.as_str(),
            "grant_type"
                | "code"
                | "redirect_uri"
                | "code_verifier"
                | "refresh_token"
                | "scope"
                | "client_id"
                | "client_secret"
                | "client_assertion_type"
                | "client_assertion"
                | "audience"
                | "resource"
        ) {
            continue;
        }
        let value = value.into_owned();
        if key == "resource" {
            let resource = parse_resource_parameter(value)?;
            if seen.contains("audience") {
                return Err(TokenFormError::DuplicateParameter);
            }
            seen.insert(key);
            if !resource_values.insert(resource.clone()) {
                return Err(TokenFormError::DuplicateParameter);
            }
            form.audiences.push(resource);
            continue;
        }
        if !seen.insert(key.clone()) {
            return Err(TokenFormError::DuplicateParameter);
        }
        match key.as_str() {
            "grant_type" => form.grant_type = value,
            "code" => form.code = non_empty(value),
            "redirect_uri" => form.redirect_uri = non_empty(value),
            "code_verifier" => form.code_verifier = non_empty(value),
            "refresh_token" => form.refresh_token = non_empty(value),
            "scope" => form.scope = non_empty(value),
            "client_id" => form.client_id = non_empty(value),
            "client_secret" => form.client_secret = non_empty(value),
            "client_assertion_type" => form.client_assertion_type = non_empty(value),
            "client_assertion" => form.client_assertion = non_empty(value),
            "audience" => {
                if !form.audiences.is_empty() {
                    return Err(TokenFormError::DuplicateParameter);
                }
                if let Some(value) = non_empty(value) {
                    form.audiences.push(value);
                }
            }
            _ => {}
        }
    }

    if form.grant_type.trim().is_empty() {
        return Err(TokenFormError::MissingGrantType);
    }
    Ok(form)
}

pub(crate) fn parse_token_management_form(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<TokenOnlyForm, TokenManagementFormError> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(TokenManagementFormError::InvalidContentType);
    }

    let raw = std::str::from_utf8(body).map_err(|_| TokenManagementFormError::InvalidEncoding)?;
    let mut seen = std::collections::HashSet::new();
    let mut form = TokenOnlyForm {
        token: String::new(),
        token_type_hint: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };

    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        if !matches!(
            key.as_str(),
            "token"
                | "token_type_hint"
                | "client_id"
                | "client_secret"
                | "client_assertion_type"
                | "client_assertion"
        ) {
            continue;
        }
        if !seen.insert(key.clone()) {
            return Err(TokenManagementFormError::DuplicateParameter);
        }
        let value = value.into_owned();
        match key.as_str() {
            "token" => form.token = value,
            "token_type_hint" => form.token_type_hint = non_empty(value),
            "client_id" => form.client_id = non_empty(value),
            "client_secret" => form.client_secret = non_empty(value),
            "client_assertion_type" => form.client_assertion_type = non_empty(value),
            "client_assertion" => form.client_assertion = non_empty(value),
            _ => {}
        }
    }

    if form.token.trim().is_empty() {
        return Err(TokenManagementFormError::MissingToken);
    }
    Ok(form)
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn parse_resource_parameter(value: String) -> Result<String, TokenFormError> {
    let parsed = url::Url::parse(&value).map_err(|_| TokenFormError::InvalidResourceParameter)?;
    if parsed.fragment().is_some() {
        return Err(TokenFormError::InvalidResourceParameter);
    }
    Ok(value)
}

#[cfg(test)]
#[path = "tests/forms.rs"]
mod tests;
