use std::fmt::Write as _;

use actix_web::{HttpResponse, http::header};

use crate::html::HtmlAttribute;

/// Renders the OpenID Connect Form Post Response Mode as a non-cacheable,
/// frame-denied auto-submitting HTML document.
#[must_use]
pub fn form_post_authorization_response(
    action: &str,
    parameters: &[(String, String)],
    session_state: Option<&str>,
    csp_nonce: &str,
) -> HttpResponse {
    let form_action = form_action_source(action);
    let nonce = HtmlAttribute(csp_nonce);
    let mut body = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Continue</title></head>\
         <body><form method=\"post\" action=\"{}\">\n",
        HtmlAttribute(action),
    );
    for (name, value) in parameters {
        writeln!(
            body,
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            HtmlAttribute(name),
            HtmlAttribute(value)
        )
        .expect("String formatting is infallible");
    }
    if let Some(value) = session_state {
        writeln!(
            body,
            "<input type=\"hidden\" name=\"session_state\" value=\"{}\">",
            HtmlAttribute(value)
        )
        .expect("String formatting is infallible");
    }
    write!(
        body,
        "<noscript><button type=\"submit\">Continue</button></noscript>\
         </form><script nonce=\"{nonce}\">document.forms[0].submit();</script></body></html>"
    )
    .expect("String formatting is infallible");
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
