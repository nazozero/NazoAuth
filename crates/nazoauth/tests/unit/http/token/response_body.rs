pub(crate) async fn oauth_error_code<B>(response: actix_web::HttpResponse<B>) -> String
where
    B: actix_web::body::MessageBody,
    B::Error: std::fmt::Debug,
{
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("OAuth error body should be readable");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    json.get("error")
        .and_then(serde_json::Value::as_str)
        .expect("OAuth JSON should contain a string error code")
        .to_owned()
}

/// Diagnostics contain only HTTP status and a fixed OAuth error category.
pub(crate) async fn oauth_error_summary<B>(response: actix_web::HttpResponse<B>) -> String
where
    B: actix_web::body::MessageBody,
    B::Error: std::fmt::Debug,
{
    let status = response.status();
    let category = match actix_web::body::to_bytes(response.into_body()).await {
        Ok(bytes) => {
            let body = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
            match body
                .as_ref()
                .and_then(|json| json.get("error"))
                .and_then(serde_json::Value::as_str)
            {
                Some("invalid_client") => "invalid_client",
                Some("invalid_grant") => "invalid_grant",
                Some("invalid_request") => "invalid_request",
                Some("invalid_dpop_proof") => "invalid_dpop_proof",
                Some("unauthorized_client") => "unauthorized_client",
                Some("server_error") => "server_error",
                Some("temporarily_unavailable") => "temporarily_unavailable",
                _ => "unrecognized_response",
            }
        }
        Err(_) => "unreadable_response",
    };
    format!("{status}: {category}")
}
