//! One-use, high-entropy offline enrollment ticket. No password verifier,
//! account creation, or public identity bootstrap endpoint is involved.
use bytes::Bytes;
use http::{Response, StatusCode, header};
use http_body_util::Full;
use jiff::Timestamp;
use nazo_identity::UserId;
use nazo_oauth_server_d1::{D1Provider, Database};
use worker::{Env, HttpRequest};

use crate::WorkerApplication;

const HTML: &str = include_str!("setup.html");
const SCRIPT: &str = include_str!("setup.js");
const LOGIN_HTML: &str = include_str!("passkey-login.html");
const LOGIN_SCRIPT: &str = include_str!("passkey-login.js");

pub async fn handle(
    request: &HttpRequest,
    env: &Env,
    application: &WorkerApplication,
) -> Option<Response<Full<Bytes>>> {
    match (request.method().as_str(), request.uri().path()) {
        ("POST", "/auth/setup/claim") => Some(claim(request, env, application).await),
        _ => None,
    }
}

pub(crate) fn page(path: &str) -> Option<Response<Full<Bytes>>> {
    let (html, script) = match path {
        "/auth/setup" => (HTML, false),
        "/auth" | "/auth/passkey" => (LOGIN_HTML, false),
        "/consent" => (include_str!("consent.html"), false),
        "/device" => (include_str!("device.html"), false),
        "/auth/setup.js" => (SCRIPT, true),
        "/auth/passkey.js" => (LOGIN_SCRIPT, true),
        "/consent.js" => (include_str!("consent.js"), true),
        "/device.js" => (include_str!("device.js"), true),
        _ => return None,
    };
    if script {
        return Some(reply(
            StatusCode::OK,
            Bytes::from_static(html.as_bytes()),
            "text/javascript; charset=utf-8",
        ));
    }
    let mut response = reply(
        StatusCode::OK,
        Bytes::from_static(html.as_bytes()),
        "text/html; charset=utf-8",
    );
    let policy = if path == "/consent" {
        // The decision endpoint performs the registered client's redirect.
        "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    } else {
        "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
    };
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        http::HeaderValue::from_static(policy),
    );
    Some(response)
}

async fn claim(
    request: &HttpRequest,
    env: &Env,
    application: &WorkerApplication,
) -> Response<Full<Bytes>> {
    let config = &application.configuration;
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if origin != Some(config.issuer.as_str()) {
        return reply(StatusCode::FORBIDDEN, Bytes::new(), "text/plain");
    }
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return reply(StatusCode::FORBIDDEN, Bytes::new(), "text/plain");
    };
    let Ok(expected) = env.secret("NAZO_BOOTSTRAP_TOKEN") else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain");
    };
    if !constant_time_ticket(token, &expected.to_string()) {
        return reply(StatusCode::FORBIDDEN, Bytes::new(), "text/plain");
    }
    let Ok(expiry) = env.secret("NAZO_BOOTSTRAP_EXPIRES_AT") else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain");
    };
    let Ok(expiry) = expiry.to_string().parse::<i64>() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain");
    };
    let now = Timestamp::now();
    if now.as_second() >= expiry {
        return reply(StatusCode::GONE, Bytes::new(), "text/plain");
    }
    let Ok(user) = env.secret("NAZO_BOOTSTRAP_USER_ID") else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain");
    };
    let Ok(user_id) = user
        .to_string()
        .parse::<uuid::Uuid>()
        .ok()
        .and_then(|id| UserId::new(id).ok())
        .ok_or(())
    else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain");
    };
    let session_id = nazo_oauth_server::crypto::random_urlsafe_token();
    let csrf_token = nazo_oauth_server::crypto::random_urlsafe_token();
    let Ok(db) = env.d1("NAZO_DB") else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain");
    };
    let provider = D1Provider::new(Database::from_binding(db), config.tenant.tenant_id);
    let digest = nazo_oauth_server::crypto::blake3_hex(token);
    match provider
        .claim_passkey_setup(&digest, user_id, &session_id, now)
        .await
    {
        Ok(true) => {}
        Ok(false) => return reply(StatusCode::FORBIDDEN, Bytes::new(), "text/plain"),
        Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain"),
    }
    let mut response = reply(
        StatusCode::OK,
        Bytes::from(serde_json::json!({ "csrf_token": csrf_token, "expires_in": 300 }).to_string()),
        "application/json; charset=utf-8",
    );
    let secure = if application.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    let session_cookie = format!(
        "{}={session_id}; Path=/; Max-Age=300; HttpOnly; SameSite=Strict{secure}",
        application.session_cookie_name,
    );
    let csrf_cookie = format!(
        "{}={csrf_token}; Path=/; Max-Age=300; SameSite=Strict{secure}",
        application.csrf_cookie_name,
    );
    let (Ok(session_cookie), Ok(csrf_cookie)) = (
        http::HeaderValue::from_str(&session_cookie),
        http::HeaderValue::from_str(&csrf_cookie),
    ) else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, Bytes::new(), "text/plain");
    };
    response
        .headers_mut()
        .append(header::SET_COOKIE, session_cookie);
    response
        .headers_mut()
        .append(header::SET_COOKIE, csrf_cookie);
    response
}

fn constant_time_ticket(provided: &str, expected: &str) -> bool {
    // Both values represent 32 random bytes in unpadded base64url form.
    if provided.len() != 43 || expected.len() != 43 {
        return false;
    }
    provided
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn reply(status: StatusCode, content: Bytes, content_type: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(content));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        http::HeaderValue::from_static("no-referrer"),
    );
    response
}
