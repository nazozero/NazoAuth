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
    pub(crate) audience: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct TokenOnlyForm {
    pub(crate) token: String,
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
    MissingGrantType,
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
        audience: None,
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
        ) {
            continue;
        }
        if !seen.insert(key.clone()) {
            return Err(TokenFormError::DuplicateParameter);
        }
        let value = value.into_owned();
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
            "audience" => form.audience = non_empty(value),
            _ => {}
        }
    }

    if form.grant_type.trim().is_empty() {
        return Err(TokenFormError::MissingGrantType);
    }
    Ok(form)
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn token_form_rejects_duplicate_defined_parameters() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let result = parse_token_form(
            &req,
            &Bytes::from_static(b"grant_type=authorization_code&grant_type=refresh_token"),
        );

        assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
    }

    #[test]
    fn token_form_ignores_unknown_parameters() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let form = parse_token_form(
            &req,
            &Bytes::from_static(b"grant_type=client_credentials&unknown=a"),
        )
        .unwrap();

        assert_eq!(form.grant_type, "client_credentials");
    }
}
