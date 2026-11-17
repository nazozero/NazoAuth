use actix_web::HttpResponse;
pub(crate) fn form_post_authorization_response(
    action: &str,
    parameters: &[(String, String)],
    session_state: Option<&str>,
    csp_nonce: &str,
) -> HttpResponse {
    nazo_http_actix::forward_response(
        nazoauth::test_support::http::form_post_authorization_response(
            action,
            parameters,
            session_state,
            csp_nonce,
        ),
    )
}
