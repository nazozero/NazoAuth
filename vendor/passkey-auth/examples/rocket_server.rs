//! Working end-to-end passkey demo using Rocket 0.5.
//!
//! Run with:
//!     cargo run --example rocket_server
//!
//! Then open http://localhost:3000 in a passkey-capable browser
//! (Chrome 108+, Safari 16+, Firefox 122+, Edge 108+). Mirrors the
//! axum_server example exactly - same HTML page, same endpoints,
//! same in-memory state model. Different framework.
//!
//! NOT FOR PRODUCTION: see the warnings in `examples/axum_server.rs`.
//! In-memory user / credential / challenge store; single hard-coded
//! user; no CSRF protection on the start endpoints; cookie-only
//! session id with no rotation.

use std::collections::HashMap;
use std::sync::Mutex;

use rocket::http::{Cookie, CookieJar, Status};
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::{State, fs::FileServer, get, launch, post, routes};
use serde::Serialize;

use passkey_auth::{
    Attachment, AuthenticationChallenge, AuthenticationResponse, AuthenticationState,
    PasskeyCredential, RegistrationChallenge, RegistrationResponse, RegistrationState, Webauthn,
};

// ---------- in-memory state -----------------------------------------------

#[derive(Default)]
struct User {
    /// Stable opaque ID we hand to the WebAuthn ceremony as user_id.
    id: Vec<u8>,
    credentials: Vec<PasskeyCredential>,
}

#[derive(Default)]
struct Session {
    reg_state: Option<RegistrationState>,
    auth_state: Option<AuthenticationState>,
}

struct AppState {
    user: Mutex<User>,
    sessions: Mutex<HashMap<String, Session>>,
    wa: Webauthn,
}

// ---------- handlers ------------------------------------------------------

/// POST /register/start - issue a registration challenge.
#[post("/register/start")]
fn register_start(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<Json<RegistrationChallenge>, Custom<String>> {
    let sid = sid_or_new(cookies);

    let mut user_guard = state.user.lock().unwrap();
    let user_id = if user_guard.id.is_empty() {
        let id = rand_bytes(16);
        user_guard.id = id.clone();
        id
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
        .unwrap()
        .entry(sid)
        .or_default()
        .reg_state = Some(reg_state);

    Ok(Json(challenge))
}

/// POST /register/finish - verify the registration response.
#[post("/register/finish", data = "<body>")]
fn register_finish(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
    body: Json<RegistrationResponse>,
) -> Result<Json<RegisterFinishReply>, Custom<String>> {
    let sid = cookies
        .get("sid")
        .map(|c| c.value().to_owned())
        .ok_or_else(|| Custom(Status::BadRequest, "missing sid cookie".into()))?;
    let reg_state = state
        .sessions
        .lock()
        .unwrap()
        .get_mut(&sid)
        .and_then(|s| s.reg_state.take())
        .ok_or_else(|| Custom(Status::BadRequest, "no registration in flight".into()))?;

    let credential = state
        .wa
        .finish_registration(&reg_state, &body)
        .map_err(|e| {
            Custom(
                Status::Unauthorized,
                format!("registration verify failed: {e}"),
            )
        })?;

    let cred_id_b64 = credential.id.to_b64url();
    state.user.lock().unwrap().credentials.push(credential);

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
#[post("/authenticate/start")]
fn authenticate_start(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<Json<AuthenticationChallenge>, Custom<String>> {
    let sid = sid_or_new(cookies);

    let user_guard = state.user.lock().unwrap();
    if user_guard.credentials.is_empty() {
        return Err(Custom(
            Status::BadRequest,
            "no registered credentials - register first".into(),
        ));
    }
    let creds = user_guard.credentials.clone();
    drop(user_guard);

    let (challenge, auth_state) = state.wa.start_authentication_with_creds(&creds);

    state
        .sessions
        .lock()
        .unwrap()
        .entry(sid)
        .or_default()
        .auth_state = Some(auth_state);

    Ok(Json(challenge))
}

/// POST /authenticate/finish - verify the assertion.
#[post("/authenticate/finish", data = "<body>")]
fn authenticate_finish(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
    body: Json<AuthenticationResponse>,
) -> Result<Json<AuthFinishReply>, Custom<String>> {
    let sid = cookies
        .get("sid")
        .map(|c| c.value().to_owned())
        .ok_or_else(|| Custom(Status::BadRequest, "missing sid cookie".into()))?;
    let auth_state = state
        .sessions
        .lock()
        .unwrap()
        .get_mut(&sid)
        .and_then(|s| s.auth_state.take())
        .ok_or_else(|| Custom(Status::BadRequest, "no authentication in flight".into()))?;

    let asserted_id = passkey_auth::CredentialId::from_b64url(&body.id)
        .map_err(|_| Custom(Status::BadRequest, "bad credential id".into()))?;
    let mut user_guard = state.user.lock().unwrap();
    let stored = user_guard
        .credentials
        .iter_mut()
        .find(|c| c.id == asserted_id)
        .ok_or_else(|| Custom(Status::Unauthorized, "unknown credential".into()))?;

    let outcome = state
        .wa
        .finish_authentication(&auth_state, &body, stored)
        .map_err(|e| Custom(Status::Unauthorized, format!("auth verify failed: {e}")))?;

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

/// Health-check endpoint. Useful to confirm the server is up before
/// loading the browser page.
#[get("/healthz")]
fn healthz() -> &'static str {
    "ok"
}

// ---------- helpers -------------------------------------------------------

/// Return the existing sid cookie, or mint a fresh one (and pin it
/// onto the cookie jar so the next response carries it).
fn sid_or_new(cookies: &CookieJar<'_>) -> String {
    if let Some(c) = cookies.get("sid") {
        return c.value().to_owned();
    }
    let sid = hex_random(16);
    cookies.add(
        Cookie::build(("sid", sid.clone()))
            .http_only(true)
            .same_site(rocket::http::SameSite::Lax)
            .path("/"),
    );
    sid
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

// ---------- launch --------------------------------------------------------

#[launch]
fn rocket() -> _ {
    let wa = Webauthn::new("localhost", "Passkey demo", "http://localhost:3000")
        // `Any` so users can register either a built-in passkey
        // (Touch ID, Windows Hello) OR a hardware key (Yubikey).
        .authenticator_attachment(Attachment::Any)
        // UV preferred (not required) so even a hardware-key tap counts.
        // For a real production passkey deployment, flip this to true.
        .require_user_verification(false);

    let state = AppState {
        user: Mutex::new(User::default()),
        sessions: Mutex::new(HashMap::new()),
        wa,
    };

    // Rocket defaults to port 8000; the demo HTML expects 3000 (same
    // as the axum example) so we override via a figment.
    let figment = rocket::Config::figment()
        .merge(("address", "127.0.0.1"))
        .merge(("port", 3000));

    rocket::custom(figment)
        .manage(state)
        .mount(
            "/",
            routes![
                register_start,
                register_finish,
                authenticate_start,
                authenticate_finish,
                healthz,
            ],
        )
        .mount("/", FileServer::from("examples/static"))
}
