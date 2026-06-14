use super::*;

pub(super) fn parse_authorization_post_form(
    req: &HttpRequest,
    body: &Bytes,
    duplicate_parameters: &[&str],
) -> Result<HashMap<String, String>, HttpResponse> {
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
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization request must use application/x-www-form-urlencoded.",
        ));
    }
    let raw = std::str::from_utf8(body).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization request form is invalid.",
        )
    })?;
    if has_duplicate_oauth_parameter(req.query_string(), duplicate_parameters) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        ));
    }
    let mut q = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        if duplicate_parameters.contains(&key.as_str()) && !seen.insert(key.clone()) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
            ));
        }
        q.insert(key, value.into_owned());
    }
    Ok(q)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
