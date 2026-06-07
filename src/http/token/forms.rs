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
                | "resource"
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
            "audience" => {
                if form.audience.is_some() {
                    return Err(TokenFormError::DuplicateParameter);
                }
                form.audience = non_empty(value);
            }
            "resource" => {
                let resource = parse_resource_parameter(value)?;
                if form.audience.is_some() {
                    return Err(TokenFormError::DuplicateParameter);
                }
                form.audience = Some(resource);
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
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use proptest::prelude::*;

    fn form_request() -> HttpRequest {
        TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request()
    }

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

    #[test]
    fn token_form_accepts_standard_resource_parameter_as_audience() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let form = parse_token_form(
            &req,
            &Bytes::from_static(
                b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com",
            ),
        )
        .unwrap();

        assert_eq!(form.audience.as_deref(), Some("https://api.example.com"));
    }

    #[test]
    fn token_form_rejects_invalid_resource_parameter() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let result = parse_token_form(
            &req,
            &Bytes::from_static(b"grant_type=client_credentials&resource=api"),
        );

        assert!(matches!(
            result,
            Err(TokenFormError::InvalidResourceParameter)
        ));
    }

    #[test]
    fn token_form_rejects_conflicting_resource_and_audience() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let result = parse_token_form(
            &req,
            &Bytes::from_static(
                b"grant_type=client_credentials&audience=resource%3A%2F%2Fdefault&resource=https%3A%2F%2Fapi.example.com",
            ),
        );

        assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));

        let result = parse_token_form(
            &req,
            &Bytes::from_static(
                b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&audience=resource%3A%2F%2Fdefault",
            ),
        );

        assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
    }

    #[test]
    fn token_management_form_rejects_duplicate_defined_parameters() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let result =
            parse_token_management_form(&req, &Bytes::from_static(b"token=token-1&token=token-2"));

        assert!(matches!(
            result,
            Err(TokenManagementFormError::DuplicateParameter)
        ));
    }

    #[test]
    fn token_management_form_tracks_token_type_hint_duplicates() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let result = parse_token_management_form(
            &req,
            &Bytes::from_static(
                b"token=token-1&token_type_hint=access_token&token_type_hint=refresh_token",
            ),
        );

        assert!(matches!(
            result,
            Err(TokenManagementFormError::DuplicateParameter)
        ));
    }

    #[test]
    fn token_management_form_accepts_token_type_hint_without_requiring_known_value() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let form = parse_token_management_form(
            &req,
            &Bytes::from_static(b"token=token-1&token_type_hint=opaque_hint"),
        )
        .unwrap();

        assert_eq!(form.token, "token-1");
        assert_eq!(form.token_type_hint.as_deref(), Some("opaque_hint"));
    }

    #[test]
    fn token_management_form_requires_form_content_type() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request();

        let result = parse_token_management_form(&req, &Bytes::from_static(b"token=token-1"));

        assert!(matches!(
            result,
            Err(TokenManagementFormError::InvalidContentType)
        ));
    }

    #[test]
    fn token_management_form_requires_non_empty_token() {
        let req = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();

        let result = parse_token_management_form(&req, &Bytes::from_static(b"token="));

        assert!(matches!(
            result,
            Err(TokenManagementFormError::MissingToken)
        ));
    }

    #[test]
    fn token_management_form_error_is_not_cacheable() {
        let response = token_management_form_error(TokenManagementFormError::MissingToken);

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
        assert_eq!(
            response.headers().get(header::PRAGMA).unwrap(),
            HeaderValue::from_static("no-cache")
        );
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    }

    proptest! {
        #[test]
        fn resource_parameter_accepts_absolute_uris_without_fragments(
            host in "[a-z][a-z0-9]{0,12}\\.example",
            path in "[a-zA-Z0-9/_-]{0,32}",
            query in prop::option::of("[a-zA-Z0-9_=&-]{1,32}")
        ) {
            let req = form_request();
            let query_suffix = query
                .as_deref()
                .map(|value| format!("?{value}"))
                .unwrap_or_default();
            let resource = format!("https://{host}/{path}{query_suffix}");
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "client_credentials")
                .append_pair("resource", &resource)
                .finish();

            let form = parse_token_form(&req, &Bytes::from(encoded)).unwrap();

            prop_assert_eq!(form.audience.as_deref(), Some(resource.as_str()));
        }

        #[test]
        fn resource_parameter_rejects_relative_or_fragment_uris(
            resource in "[a-zA-Z0-9/_-]{1,32}",
            fragment in "[a-zA-Z0-9_-]{1,16}"
        ) {
            let req = form_request();
            let relative = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "client_credentials")
                .append_pair("resource", &resource)
                .finish();
            let with_fragment = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "client_credentials")
                .append_pair("resource", &format!("https://api.example/{resource}#{fragment}"))
                .finish();

            prop_assert!(matches!(
                parse_token_form(&req, &Bytes::from(relative)),
                Err(TokenFormError::InvalidResourceParameter)
            ));
            prop_assert!(matches!(
                parse_token_form(&req, &Bytes::from(with_fragment)),
                Err(TokenFormError::InvalidResourceParameter)
            ));
        }

        #[test]
        fn duplicate_defined_parameters_are_rejected_regardless_of_value(
            first in "[a-zA-Z0-9_-]{0,16}",
            second in "[a-zA-Z0-9_-]{0,16}"
        ) {
            let req = form_request();
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "client_credentials")
                .append_pair("client_id", &first)
                .append_pair("client_id", &second)
                .finish();

            prop_assert!(matches!(
                parse_token_form(&req, &Bytes::from(body)),
                Err(TokenFormError::DuplicateParameter)
            ));
        }
    }
}
