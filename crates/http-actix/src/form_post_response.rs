use actix_web::{HttpResponse, http::header};

/// Renders the OpenID Connect Form Post Response Mode as a non-cacheable,
/// frame-denied auto-submitting HTML document.
#[must_use]
pub fn form_post_authorization_response(
    action: &str,
    parameters: &[(String, String)],
    session_state: Option<&str>,
    csp_nonce: &str,
) -> HttpResponse {
    let mut inputs = String::new();
    for (name, value) in parameters {
        inputs.push_str("<input type=\"hidden\" name=\"");
        inputs.push_str(&escape_html_attribute(name));
        inputs.push_str("\" value=\"");
        inputs.push_str(&escape_html_attribute(value));
        inputs.push_str("\">\n");
    }
    if let Some(value) = session_state {
        inputs.push_str("<input type=\"hidden\" name=\"session_state\" value=\"");
        inputs.push_str(&escape_html_attribute(value));
        inputs.push_str("\">\n");
    }
    let form_action = form_action_source(action);
    let action = escape_html_attribute(action);
    let nonce = escape_html_attribute(csp_nonce);
    let body = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Continue</title></head>\
         <body><form method=\"post\" action=\"{action}\">\n{inputs}<noscript><button type=\"submit\">Continue</button></noscript>\
         </form><script nonce=\"{nonce}\">document.forms[0].submit();</script></body></html>"
    );
    let csp = format!(
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action {form_action}; script-src 'nonce-{nonce}'"
    );
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::PRAGMA, "no-cache"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Content-Security-Policy", csp))
        .body(body)
}

fn form_action_source(action: &str) -> String {
    url::Url::parse(action)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| "'none'".to_owned())
}

fn escape_html_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(character),
        }
    }
    escaped
}
