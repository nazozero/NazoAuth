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
