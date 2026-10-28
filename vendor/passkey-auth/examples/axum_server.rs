//! Working end-to-end passkey demo using Axum.
//!
//! Run with:
//!     cargo run --example axum_server
//!
//! Then open http://localhost:3000 in a passkey-capable browser
//! (Chrome 108+, Safari 16+, Firefox 122+, Edge 108+). The page
//! lets you register a passkey for "alice@example.com" and then
//! authenticate with it.
//!
//! NOT FOR PRODUCTION:
//!   - In-memory user / credential / challenge store (lost on restart).
//!   - Single hard-coded user.
//!   - No CSRF protection on the start endpoints.
//!   - Session = a random cookie; no expiry / rotation.
//!   - Listens on http://localhost (passkeys also work without TLS
//!     on localhost specifically; in production you MUST use HTTPS).
//!
//! Use this as a reference for wiring `passkey-auth` into your own
//! server, not as a copy-paste production starter.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;
use tokio::sync::Mutex;
// No CORS layer: every endpoint is same-origin with the static HTML.
// `CorsLayer::permissive()` was a defensive copy from internet
// examples; for a passkey server it is exactly the wrong default
// (allows credentialed cross-origin requests, neutering the browser
// origin check on the /whoami and /authenticate endpoints).
use tower_http::services::ServeDir;

use passkey_auth::{
    Attachment, AuthenticationResponse, AuthenticationState, PasskeyCredential,
    RegistrationResponse, RegistrationState, Webauthn,
};

// ---------- in-memory state -----------------------------------------------

/// What we keep about each registered user. A real app would store
/// this in Postgres / SQLite / wherever.
#[derive(Default)]
struct User {
    /// Stable opaque ID we hand to the WebAuthn ceremony as user_id.
    id: Vec<u8>,
    credentials: Vec<PasskeyCredential>,
}

/// Per-session state. Keyed by the `sid` cookie. Holds whichever
/// ceremony is currently in flight (at most one).
#[derive(Default)]
struct Session {
    reg_state: Option<RegistrationState>,
    auth_state: Option<AuthenticationState>,
}

struct AppState {
    /// The single demo user. A real app would key by user id.
    user: Mutex<User>,
    /// sid -> Session
    sessions: Mutex<HashMap<String, Session>>,
    /// The WebAuthn façade, configured once at boot.
    wa: Webauthn,
}

// ---------- handlers ------------------------------------------------------

/// POST /register/start - issue a challenge.
/// Returns a [`RegistrationChallenge`] verbatim - it already has the
/// JSON field shapes that `navigator.credentials.create` needs.
async fn register_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_or_create_sid(&cookies);

    let user_guard = state.user.lock().await;
    let user_id = if user_guard.id.is_empty() {
        // First-time register: assign a stable user id.
        rand_bytes(16)
    } else {
        user_guard.id.clone()
    };
    let existing: Vec<_> = user_guard
        .credentials
        .iter()
        .map(|c| c.id.clone())
        .collect();
    drop(user_guard);

    let (challenge, reg_state) =
        state
            .wa
            .start_registration(&user_id, "alice@example.com", "Alice", &existing);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .reg_state = Some(reg_state);

    // Persist the user id so finish_registration uses the same one.
    let mut user_guard = state.user.lock().await;
    if user_guard.id.is_empty() {
        user_guard.id = user_id;
    }

    Ok(json_with_sid(&challenge, &sid))
}

/// POST /register/finish - verify the registration response.
async fn register_finish(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
    Json(body): Json<RegistrationResponse>,
) -> Result<Json<RegisterFinishReply>, AppError> {
    let sid = sid_from_cookies(&cookies).ok_or(AppError::BadRequest("missing sid cookie"))?;
    let reg_state = state
        .sessions
        .lock()
        .await
        .get_mut(&sid)
        .and_then(|s| s.reg_state.take())
        .ok_or(AppError::BadRequest("no registration in flight"))?;

    let credential = state
        .wa
        .finish_registration(&reg_state, &body)
        .map_err(|e| AppError::Unauthorized(format!("registration verify failed: {e}")))?;

    let cred_id_b64 = credential.id.to_b64url();
    state.user.lock().await.credentials.push(credential);

    Ok(Json(RegisterFinishReply {
        ok: true,
        credential_id: cred_id_b64,
    }))
}

#[derive(Serialize)]
struct RegisterFinishReply {
    ok: bool,
    credential_id: String,
}

/// POST /authenticate/start - issue an assertion challenge.
async fn authenticate_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_or_create_sid(&cookies);

    let user_guard = state.user.lock().await;
    if user_guard.credentials.is_empty() {
        return Err(AppError::BadRequest(
            "no registered credentials - register first",
        ));
    }
    let creds = user_guard.credentials.clone();
    drop(user_guard);

    let (challenge, auth_state) = state.wa.start_authentication_with_creds(&creds);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .auth_state = Some(auth_state);

    Ok(json_with_sid(&challenge, &sid))
}

/// POST /authenticate/finish - verify the assertion.
async fn authenticate_finish(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
    Json(body): Json<AuthenticationResponse>,
) -> Result<Json<AuthFinishReply>, AppError> {
    let sid = sid_from_cookies(&cookies).ok_or(AppError::BadRequest("missing sid cookie"))?;
    let auth_state = state
        .sessions
        .lock()
        .await
        .get_mut(&sid)
        .and_then(|s| s.auth_state.take())
        .ok_or(AppError::BadRequest("no authentication in flight"))?;

    // Look up the stored credential the user is asserting with.
    let asserted_id = passkey_auth::CredentialId::from_b64url(&body.id)
        .map_err(|_| AppError::BadRequest("bad credential id"))?;
    let mut user_guard = state.user.lock().await;
    let stored = user_guard
        .credentials
        .iter_mut()
        .find(|c| c.id == asserted_id)
        .ok_or(AppError::Unauthorized("unknown credential".into()))?;

    let outcome = state
        .wa
        .finish_authentication(&auth_state, &body, stored)
        .map_err(|e| AppError::Unauthorized(format!("auth verify failed: {e}")))?;

    // Update the stored counter (per the spec).
    stored.counter = outcome.new_counter;

    Ok(Json(AuthFinishReply {
        ok: true,
        user_verified: outcome.user_verified,
        new_counter: outcome.new_counter,
    }))
}

#[derive(Serialize)]
struct AuthFinishReply {
    ok: bool,
    user_verified: bool,
    new_counter: u32,
}

// ---------- helpers -------------------------------------------------------

/// Generate or recover the session id. Each browser tab gets one.
fn get_or_create_sid(cookies: &HeaderMap) -> String {
    sid_from_cookies(cookies).unwrap_or_else(|| hex_random(16))
}

fn sid_from_cookies(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for cookie in raw.split(';') {
        let cookie = cookie.trim();
        if let Some(rest) = cookie.strip_prefix("sid=") {
            return Some(rest.to_owned());
        }
    }
    None
}

/// Attach a Set-Cookie header that pins the session id, then JSON-encode
/// the body. Cookie is HttpOnly + SameSite=Lax; we are HTTP-only so no
/// Secure flag.
fn json_with_sid<T: Serialize>(body: &T, sid: &str) -> Response {
    let mut resp = Json(body).into_response();
    let cookie = format!("sid={sid}; HttpOnly; SameSite=Lax; Path=/");
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie ascii"),
    );
    resp
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn hex_random(n: usize) -> String {
    hex::encode(rand_bytes(n))
}

// ---------- errors --------------------------------------------------------

#[derive(Debug)]
enum AppError {
    BadRequest(&'static str),
    Unauthorized(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m.to_owned()),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
        };
        (code, msg).into_response()
    }
}

// ---------- main ----------------------------------------------------------

#[tokio::main]
async fn main() {
    let wa = Webauthn::new("localhost", "Passkey demo", "http://localhost:3000")
        // `Any` so users can register either a built-in passkey
        // (Touch ID, Windows Hello) OR a hardware key (Yubikey).
        .authenticator_attachment(Attachment::Any)
        // UV preferred (not required) so even a hardware-key tap counts.
        // For a real production passkey deployment, flip this to true.
        .require_user_verification(false);

    let state = Arc::new(AppState {
        user: Mutex::new(User::default()),
        sessions: Mutex::new(HashMap::new()),
        wa,
    });

    let app = Router::new()
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/authenticate/start", post(authenticate_start))
        .route("/authenticate/finish", post(authenticate_finish))
        // Serve everything under examples/static/ at the root. Index.html
        // is the demo UI.
        .fallback_service(ServeDir::new("examples/static"))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("passkey demo listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
