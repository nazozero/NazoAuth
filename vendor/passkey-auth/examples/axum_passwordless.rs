//! Passwordless (discoverable-credential) Axum demo.
//!
//! Run with:
//!     cargo run --example axum_passwordless
//!
//! Then open http://localhost:3000 in a passkey-capable browser.
//!
//! What is different from `axum_server`:
//!
//! - **Multiple users.** Keyed by username; each user owns one or more
//!   credentials.
//! - **Usernameless sign-in.** `start_authentication` is called with an
//!   EMPTY allow_credentials list. The browser surfaces every passkey
//!   it knows for this RP (across whichever accounts the user has
//!   registered) and lets them pick. This is the Gmail / passkeys.io
//!   "tap to sign in" flow.
//! - **user_handle lookup.** Because the server has no idea which user
//!   is asserting until the response comes back, the credential is
//!   looked up by the response's `userHandle` (the opaque user id we
//!   minted at registration time).
//!
//! For this flow to work, the registration challenge sets
//! `residentKey: "required"` — instructs the authenticator to store
//! the credential locally as a discoverable credential. The crate
//! already defaults to "preferred" which is enough for built-in
//! passkey authenticators (Touch ID, Windows Hello, iCloud Keychain);
//! we override to "required" here to make the demo robust on hardware
//! keys too.
//!
//! NOT FOR PRODUCTION: in-memory state, no rate limiting, sessions
//! are unsigned cookies. See axum_server.rs for the broader warnings.

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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
// See axum_server.rs for why we do NOT install CorsLayer::permissive().
use tower_http::services::ServeDir;

use passkey_auth::{
    Attachment, AuthenticationResponse, AuthenticationState, CredentialId, PasskeyCredential,
    RegistrationResponse, RegistrationState, Webauthn,
};

// ---------- in-memory state -----------------------------------------------

#[derive(Default, Clone)]
struct User {
    /// The stable opaque user id we hand to the WebAuthn ceremony.
    /// Derived from the username so it survives restarts within a
    /// process; a real app would store it in the DB.
    handle: Vec<u8>,
    credentials: Vec<PasskeyCredential>,
}

#[derive(Default)]
struct Session {
    /// Ceremony in flight: registration. Keyed off the username the
    /// user typed in.
    reg_state: Option<(String, RegistrationState)>,
    /// Ceremony in flight: authentication. No username yet because
    /// the user has not picked their credential.
    auth_state: Option<AuthenticationState>,
    /// After a successful authentication, which user is signed in.
    signed_in_as: Option<String>,
}

struct AppState {
    /// username -> User
    users: Mutex<HashMap<String, User>>,
    /// sid cookie -> Session
    sessions: Mutex<HashMap<String, Session>>,
    wa: Webauthn,
}

// ---------- handlers ------------------------------------------------------

#[derive(Deserialize)]
struct RegisterStartReq {
    username: String,
}

/// POST /register/start - issue a registration challenge for a NEW user.
async fn register_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
    Json(body): Json<RegisterStartReq>,
) -> Result<Response, AppError> {
    let username = body.username.trim().to_owned();
    if username.is_empty() {
        return Err(AppError::BadRequest("username required"));
    }
    let sid = get_or_create_sid(&cookies);

    // Refuse if the username is already taken. A real app would
    // either prompt the user to sign in instead or let them add a
    // device (see rocket_credential_manager.rs for that pattern).
    let users = state.users.lock().await;
    if users.contains_key(&username) {
        return Err(AppError::BadRequest(
            "username already exists - sign in instead",
        ));
    }
    drop(users);

    // Derive a stable user_handle from the username. Real apps mint a
    // random UUID at sign-up time and store it; we hash so the demo
    // is deterministic across restarts of a single process.
    let user_handle = Sha256::digest(username.as_bytes())[..16].to_vec();

    let (challenge, reg_state) =
        state
            .wa
            .start_registration(&user_handle, &username, &username, &[]);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .reg_state = Some((username, reg_state));

    Ok(json_with_sid(&challenge, &sid))
}

/// POST /register/finish - verify the registration response and create
/// the user.
async fn register_finish(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
    Json(body): Json<RegistrationResponse>,
) -> Result<Json<RegisterFinishReply>, AppError> {
    let sid = sid_from_cookies(&cookies).ok_or(AppError::BadRequest("missing sid cookie"))?;
    let (username, reg_state) = state
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

    let mut users = state.users.lock().await;
    let entry = users.entry(username.clone()).or_default();
    entry.handle = Sha256::digest(username.as_bytes())[..16].to_vec();
    entry.credentials.push(credential);

    Ok(Json(RegisterFinishReply { ok: true, username }))
}

#[derive(Serialize)]
struct RegisterFinishReply {
    ok: bool,
    username: String,
}

/// POST /authenticate/start - issue a passwordless assertion challenge.
/// `allow_credentials` is intentionally empty - the browser picks any
/// passkey it has for this RP.
async fn authenticate_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_or_create_sid(&cookies);

    // Empty Vec<CredentialId> - this is what makes it "passwordless".
    let (challenge, auth_state) = state.wa.start_authentication(&[]);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .auth_state = Some(auth_state);

    Ok(json_with_sid(&challenge, &sid))
}

/// POST /authenticate/finish - verify the assertion. Identifies the
/// user by the response's userHandle.
///
/// On success: ROTATE the session id (mint a fresh sid, move the
/// session record to the new key, hand the new cookie back to the
/// browser). This is defence against session-fixation - if an
/// attacker tricked the victim into using an attacker-known pre-auth
/// sid, that sid is now dead and the victim's signed-in state lives
/// under a value the attacker never saw.
async fn authenticate_finish(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
    Json(body): Json<AuthenticationResponse>,
) -> Result<Response, AppError> {
    let sid = sid_from_cookies(&cookies).ok_or(AppError::BadRequest("missing sid cookie"))?;
    let auth_state = state
        .sessions
        .lock()
        .await
        .get_mut(&sid)
        .and_then(|s| s.auth_state.take())
        .ok_or(AppError::BadRequest("no authentication in flight"))?;

    // The browser sends userHandle (the opaque user_id we minted at
    // registration). Discoverable-credential flow REQUIRES it; without
    // it we cannot identify the user.
    let user_handle_b64 = body
        .user_handle
        .as_deref()
        .ok_or(AppError::BadRequest("response missing userHandle"))?;
    let user_handle = base64_decode_lenient(user_handle_b64)
        .ok_or(AppError::BadRequest("userHandle not valid base64"))?;

    // Look up the user by handle, then find the asserted credential
    // within that user's credentials.
    let asserted_id = CredentialId::from_b64url(&body.id)
        .map_err(|_| AppError::BadRequest("bad credential id"))?;

    let mut users = state.users.lock().await;
    let (username, user) = users
        .iter_mut()
        .find(|(_, u)| u.handle == user_handle)
        .ok_or(AppError::Unauthorized("unknown user".into()))?;
    let username = username.clone();
    let stored = user
        .credentials
        .iter_mut()
        .find(|c| c.id == asserted_id)
        .ok_or(AppError::Unauthorized("unknown credential for user".into()))?;

    let outcome = state
        .wa
        .finish_authentication(&auth_state, &body, stored)
        .map_err(|e| AppError::Unauthorized(format!("auth verify failed: {e}")))?;

    stored.counter = outcome.new_counter;
    drop(users);

    // ── Session rotation ────────────────────────────────────────────
    // Drop the pre-auth session record entirely and mint a fresh sid
    // for the now-signed-in state. The attacker (if any) holding the
    // old sid is left with a dead cookie.
    let new_sid = hex_random(16);
    {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&sid);
        sessions.insert(
            new_sid.clone(),
            Session {
                signed_in_as: Some(username.clone()),
                ..Session::default()
            },
        );
    }

    Ok(json_with_sid(
        &AuthFinishReply {
            ok: true,
            username,
            user_verified: outcome.user_verified,
        },
        &new_sid,
    ))
}

#[derive(Serialize)]
struct AuthFinishReply {
    ok: bool,
    username: String,
    user_verified: bool,
}

/// GET /whoami - returns the currently signed-in username, or 401.
/// Lets the JS know whether to show "Sign in" vs "Signed in as X".
async fn whoami(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Json<WhoamiReply>, AppError> {
    let sid = sid_from_cookies(&cookies).ok_or(AppError::Unauthorized("no session".into()))?;
    let sessions = state.sessions.lock().await;
    let user = sessions
        .get(&sid)
        .and_then(|s| s.signed_in_as.clone())
        .ok_or(AppError::Unauthorized("not signed in".into()))?;
    Ok(Json(WhoamiReply { username: user }))
}

#[derive(Serialize)]
struct WhoamiReply {
    username: String,
}

// ---------- helpers -------------------------------------------------------

/// Decode either url-safe or standard base64 (with or without padding).
/// Mirrors the permissive decoder inside passkey-auth itself.
fn base64_decode_lenient(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .ok()
}

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

fn json_with_sid<T: Serialize>(body: &T, sid: &str) -> Response {
    let mut resp = Json(body).into_response();
    let cookie = format!("sid={sid}; HttpOnly; SameSite=Lax; Path=/");
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie ascii"),
    );
    resp
}

fn hex_random(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

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
    let wa = Webauthn::new(
        "localhost",
        "Passkey passwordless demo",
        "http://localhost:3000",
    )
    // `Any` so users can register either a built-in passkey OR a
    // hardware key.
    .authenticator_attachment(Attachment::Any)
    // For passwordless flow we want UV - the authenticator MUST
    // confirm the user identity (Touch ID / PIN), not just presence.
    .require_user_verification(true);

    let state = Arc::new(AppState {
        users: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashMap::new()),
        wa,
    });

    let app = Router::new()
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/authenticate/start", post(authenticate_start))
        .route("/authenticate/finish", post(authenticate_finish))
        .route("/whoami", axum::routing::get(whoami))
        .fallback_service(ServeDir::new("examples/static/passwordless"))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("passwordless demo listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
