use actix_web::{HttpRequest, http::header};

pub fn request_uses_form_urlencoded(request: &HttpRequest) -> bool {
    request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

#[cfg(test)]
mod tests {
    use actix_web::{http::header, test::TestRequest};

    use super::request_uses_form_urlencoded;

    #[test]
    fn form_content_type_is_case_insensitive_and_accepts_parameters() {
        let request = TestRequest::default()
            .insert_header((
                header::CONTENT_TYPE,
                "Application/X-WWW-Form-Urlencoded; charset=utf-8",
            ))
            .to_http_request();
        assert!(request_uses_form_urlencoded(&request));

        let request = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request();
        assert!(!request_uses_form_urlencoded(&request));
    }
}
