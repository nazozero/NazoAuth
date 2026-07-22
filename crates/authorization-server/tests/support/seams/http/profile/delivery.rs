fn delivery_payload_response(raw: &str) -> HttpResponse {
    match serde_json::from_str(raw) {
        Ok(value) => delivery_value_response(value),
        Err(_) => authorization_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "凭据内容无效.",
        ),
    }
}
