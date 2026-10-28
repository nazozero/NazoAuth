//! Credential-manager Rocket demo: register many devices, remove
//! individual ones, list them.
//!
//! Run with:
//!     cargo run --example rocket_credential_manager
//!
//! Then open http://localhost:3000 in a passkey-capable browser.
//!
//! What is different from `rocket_server`:
//!
//! - Single hard-coded user (alice@example.com) but multiple
//!   credentials. Models the real "I have a Mac AND a phone" UX.
//! - After the first credential is registered, the user can sign in
//!   AND add more devices from the signed-in dashboard.
//! - Adding a new credential uses `excludeCredentials` so the user
//!   cannot accidentally register the same authenticator twice.
//! - Listing shows AAGUID + transports + counter for each credential.
//! - Removing a credential is a DELETE request.
//!
//! NOT FOR PRODUCTION: in-memory state, single hard-coded user.

use std::collections::HashMap;
use std::sync::Mutex;

use rocket::http::{Cookie, CookieJar, Status};
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::{Build, Rocket, State, fs::FileServer, get, launch, post, routes};
use serde::Serialize;

use passkey_auth::{
    Attachment, AuthenticationChallenge, AuthenticationResponse, AuthenticationState,
    PasskeyCredential, RegistrationChallenge, RegistrationResponse, RegistrationState, Webauthn,
};

const USERNAME: &str = "alice@example.com";

// ---------- in-memory state -----------------------------------------------

#[derive(Default)]
struct User {
    handle: Vec<u8>,
    credentials: Vec<PasskeyCredential>,
}

#[derive(Default)]
struct Session {
    reg_state: Option<RegistrationState>,
    auth_state: Option<AuthenticationState>,
    signed_in: bool,
}

struct AppState {
    user: Mutex<User>,
    sessions: Mutex<HashMap<String, Session>>,
    wa: Webauthn,
}

// ---------- handlers ------------------------------------------------------

/// POST /register/start - initial registration when there is no user yet.
/// Refused if the user already has at least one credential (use
/// /credentials/add for that case).
#[post("/register/start")]
fn register_start(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<Json<RegistrationChallenge>, Custom<String>> {
    let user = state.user.lock().unwrap();
    if !user.credentials.is_empty() {
        return Err(Custom(
            Status::BadRequest,
            "already registered - use /credentials/add to add another device".into(),
        ));
    }
    drop(user);

    let sid = sid_or_new(cookies);
    let user_handle = rand_bytes(16);
    state.user.lock().unwrap().handle = user_handle.clone();

    let (challenge, reg_state) = state
        .wa
        .start_registration(&user_handle, USERNAME, "Alice", &[]);

    state
        .sessions
        .lock()
        .unwrap()
        .entry(sid)
        .or_default()
        .reg_state = Some(reg_state);

    Ok(Json(challenge))
}

/// POST /register/finish - verify the initial registration.
#[post("/register/finish", data = "<body>")]
fn register_finish(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
    body: Json<RegistrationResponse>,
) -> Result<Json<RegisterFinishReply>, Custom<String>> {
    let sid = sid_from_cookies(cookies)?;
    let reg_state = take_reg_state(state, &sid)?;
    let credential = state
        .wa
        .finish_registration(&reg_state, &body)
        .map_err(|e| {
            Custom(
                Status::Unauthorized,
                format!("registration verify failed: {e}"),
            )
        })?;
    let id_b64 = credential.id.to_b64url();
    state.user.lock().unwrap().credentials.push(credential);
    Ok(Json(RegisterFinishReply {
        ok: true,
        credential_id: id_b64,
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
    let user = state.user.lock().unwrap();
    if user.credentials.is_empty() {
        return Err(Custom(
            Status::BadRequest,
            "no credentials yet - register first".into(),
        ));
    }
    let creds = user.credentials.clone();
    let handle = user.handle.clone();
    drop(user);

    let sid = sid_or_new(cookies);
    // Use the for_user variant so finish_authentication can verify
    // the assertion's userHandle matches THIS user (WebAuthn-3 §7.2
    // step 6) — defence in depth against credential-id collisions in
    // a multi-user store.
    let (challenge, auth_state) = state
        .wa
        .start_authentication_with_creds_for_user(&handle, &creds);

    state
        .sessions
        .lock()
        .unwrap()
        .entry(sid)
        .or_default()
        .auth_state = Some(auth_state);
    Ok(Json(challenge))
}

/// POST /authenticate/finish - verify, set signed_in on the session.
///
/// On success: ROTATE the session id (drop the pre-auth sid, mint a
/// fresh one, attach it to the response via Set-Cookie). Defence
/// against session-fixation: if an attacker pre-set a known sid in
/// the victim's browser, that sid is now dead and the signed-in
/// session lives under a value the attacker never saw.
#[post("/authenticate/finish", data = "<body>")]
fn authenticate_finish(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
    body: Json<AuthenticationResponse>,
) -> Result<Json<AuthFinishReply>, Custom<String>> {
    let sid = sid_from_cookies(cookies)?;
    let auth_state = take_auth_state(state, &sid)?;

    let asserted_id = passkey_auth::CredentialId::from_b64url(&body.id)
        .map_err(|_| Custom(Status::BadRequest, "bad credential id".into()))?;
    let mut user = state.user.lock().unwrap();
    let stored = user
        .credentials
        .iter_mut()
        .find(|c| c.id == asserted_id)
        .ok_or_else(|| Custom(Status::Unauthorized, "unknown credential".into()))?;
    let outcome = state
        .wa
        .finish_authentication(&auth_state, &body, stored)
        .map_err(|e| Custom(Status::Unauthorized, format!("auth verify failed: {e}")))?;
    stored.counter = outcome.new_counter;
    drop(user);

    // Rotate: drop the old session entry, create a new signed-in
    // session keyed by a fresh sid, and overwrite the cookie.
    let new_sid = hex_random(16);
    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.remove(&sid);
        sessions.insert(
            new_sid.clone(),
            Session {
                signed_in: true,
                ..Session::default()
            },
        );
    }
    cookies.add(
        Cookie::build(("sid", new_sid))
            .http_only(true)
            .same_site(rocket::http::SameSite::Lax)
            .path("/"),
    );

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

/// POST /credentials/add/start - signed-in user wants to register a
/// NEW device for the same account. The new ceremony's
/// excludeCredentials lists every existing credential so the same
/// device cannot register twice.
#[post("/credentials/add/start")]
fn add_credential_start(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<Json<RegistrationChallenge>, Custom<String>> {
    require_signed_in(state, cookies)?;
    let sid = sid_from_cookies(cookies)?;

    let user = state.user.lock().unwrap();
    let existing: Vec<_> = user.credentials.iter().map(|c| c.id.clone()).collect();
    let handle = user.handle.clone();
    drop(user);

    let (challenge, reg_state) = state
        .wa
        .start_registration(&handle, USERNAME, "Alice", &existing);
    state
        .sessions
        .lock()
        .unwrap()
        .entry(sid)
        .or_default()
        .reg_state = Some(reg_state);
    Ok(Json(challenge))
}

/// POST /credentials/add/finish - persist the new credential.
#[post("/credentials/add/finish", data = "<body>")]
fn add_credential_finish(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
    body: Json<RegistrationResponse>,
) -> Result<Json<RegisterFinishReply>, Custom<String>> {
    require_signed_in(state, cookies)?;
    let sid = sid_from_cookies(cookies)?;
    let reg_state = take_reg_state(state, &sid)?;
    let credential = state
        .wa
        .finish_registration(&reg_state, &body)
        .map_err(|e| {
            Custom(
                Status::Unauthorized,
                format!("add-credential verify failed: {e}"),
            )
        })?;
    let id_b64 = credential.id.to_b64url();
    state.user.lock().unwrap().credentials.push(credential);
    Ok(Json(RegisterFinishReply {
        ok: true,
        credential_id: id_b64,
    }))
}

/// GET /credentials - list the user's registered credentials.
/// Anyone can read this; in a real app you would gate on signed-in.
#[get("/credentials")]
fn list_credentials(state: &State<AppState>) -> Json<Vec<CredentialView>> {
    let user = state.user.lock().unwrap();
    Json(
        user.credentials
            .iter()
            .map(|c| CredentialView {
                id: c.id.to_b64url(),
                aaguid_hex: hex::encode(c.aaguid),
                transports: c.transports.clone(),
                counter: c.counter,
            })
            .collect(),
    )
}

#[derive(Serialize)]
struct CredentialView {
    id: String,
    aaguid_hex: String,
    transports: Vec<String>,
    counter: u32,
}

/// POST /credentials/<id_b64>/delete - remove a credential. Refuses
/// to delete the last one (a signed-in user with zero credentials
/// would be locked out).
///
/// Uses POST (with the id in the path) rather than DELETE because
/// the demo HTML uses fetch() without preflight - keeps the JS small.
#[post("/credentials/<id_b64>/delete")]
fn delete_credential(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
    id_b64: &str,
) -> Result<Json<DeleteReply>, Custom<String>> {
    require_signed_in(state, cookies)?;
    let target = passkey_auth::CredentialId::from_b64url(id_b64)
        .map_err(|_| Custom(Status::BadRequest, "bad credential id".into()))?;
    let mut user = state.user.lock().unwrap();
    if user.credentials.len() <= 1 {
        return Err(Custom(
            Status::BadRequest,
            "cannot delete your last credential - you would be locked out".into(),
        ));
    }
    let before = user.credentials.len();
    user.credentials.retain(|c| c.id != target);
    if user.credentials.len() == before {
        return Err(Custom(Status::BadRequest, "credential not found".into()));
    }
    Ok(Json(DeleteReply { ok: true }))
}

#[derive(Serialize)]
struct DeleteReply {
    ok: bool,
}

/// GET /whoami - "alice if signed-in, otherwise 401". Lets the page
/// decide which view to render.
#[get("/whoami")]
fn whoami(state: &State<AppState>, cookies: &CookieJar<'_>) -> Result<Json<WhoamiReply>, Status> {
    let signed_in = sid_from_cookies(cookies)
        .ok()
        .and_then(|sid| {
            state
                .sessions
                .lock()
                .unwrap()
                .get(&sid)
                .map(|s| s.signed_in)
        })
        .unwrap_or(false);
    if !signed_in {
        return Err(Status::Unauthorized);
    }
    Ok(Json(WhoamiReply {
        username: USERNAME.into(),
    }))
}

#[derive(Serialize)]
struct WhoamiReply {
    username: String,
}

// ---------- helpers -------------------------------------------------------

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

fn sid_from_cookies(cookies: &CookieJar<'_>) -> Result<String, Custom<String>> {
    cookies
        .get("sid")
        .map(|c| c.value().to_owned())
        .ok_or_else(|| Custom(Status::BadRequest, "missing sid cookie".into()))
}

fn require_signed_in(
    state: &State<AppState>,
    cookies: &CookieJar<'_>,
) -> Result<(), Custom<String>> {
    let sid = sid_from_cookies(cookies)?;
    let sessions = state.sessions.lock().unwrap();
    let ok = sessions.get(&sid).map(|s| s.signed_in).unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Custom(Status::Unauthorized, "not signed in".into()))
    }
}

fn take_reg_state(state: &State<AppState>, sid: &str) -> Result<RegistrationState, Custom<String>> {
    state
        .sessions
        .lock()
        .unwrap()
        .get_mut(sid)
        .and_then(|s| s.reg_state.take())
        .ok_or_else(|| Custom(Status::BadRequest, "no registration in flight".into()))
}

fn take_auth_state(
    state: &State<AppState>,
    sid: &str,
) -> Result<AuthenticationState, Custom<String>> {
    state
        .sessions
        .lock()
        .unwrap()
        .get_mut(sid)
        .and_then(|s| s.auth_state.take())
        .ok_or_else(|| Custom(Status::BadRequest, "no authentication in flight".into()))
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
fn rocket() -> Rocket<Build> {
    let wa = Webauthn::new(
        "localhost",
        "Passkey credential manager",
        "http://localhost:3000",
    )
    .authenticator_attachment(Attachment::Any)
    .require_user_verification(false);

    let state = AppState {
        user: Mutex::new(User::default()),
        sessions: Mutex::new(HashMap::new()),
        wa,
    };

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
                add_credential_start,
                add_credential_finish,
                list_credentials,
                delete_credential,
                whoami,
            ],
        )
        .mount("/", FileServer::from("examples/static/credential_manager"))
}
