//! SQLite-backed Axum demo. Like `axum_server`, but credentials
//! persist across restarts in a local `passkeys.db` file.
//!
//! Run with:
//!     cargo run --example axum_sqlite
//!
//! Then open http://localhost:3000. Register a passkey, kill the
//! server, run it again - the passkey is still there.
//!
//! What this example demonstrates:
//!
//! - How to persist `PasskeyCredential` to a SQL row. The mapping is
//!   straightforward: every field is either bytes, an int, or a
//!   small list-of-strings that we comma-join.
//! - How to update the counter inside `finish_authentication` BEFORE
//!   returning success. The DB is the source of truth; the in-memory
//!   copy is a cache.
//! - Why challenge / session state is NOT in the DB: challenges are
//!   single-use and last ~60 seconds. Putting them in SQLite means
//!   you also need a cleanup job. In-memory + cookie sid is simpler.
//!
//! NOT FOR PRODUCTION: SQLite blocking IO from an async handler is
//! fine for a single-process demo; under real load use the `tokio-rusqlite`
//! crate or move to a real connection-pooled driver.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
    routing::post,
};
use rusqlite::{Connection, params};
use serde::Serialize;
use tokio::sync::Mutex;
// See axum_server.rs for why we do NOT install CorsLayer::permissive().
use tower_http::services::ServeDir;

use passkey_auth::{
    Attachment, AuthenticationResponse, AuthenticationState, CosePublicKey, CredentialId,
    PasskeyCredential, RegistrationResponse, RegistrationState, Webauthn,
};

const DB_PATH: &str = "passkeys.db";
const USERNAME: &str = "alice@example.com";

// ---------- storage layer --------------------------------------------------

/// The schema. One table per concept:
///   users      - (id BLOB PRIMARY KEY, username TEXT UNIQUE NOT NULL)
///   credentials - (id BLOB PK, user_id BLOB FK, public_key_cose BLOB,
///                  counter INTEGER, transports TEXT, aaguid BLOB)
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id        BLOB PRIMARY KEY,
    username  TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS credentials (
    id              BLOB PRIMARY KEY,
    user_id         BLOB NOT NULL,
    public_key_cose BLOB NOT NULL,
    counter         INTEGER NOT NULL,
    transports      TEXT NOT NULL,
    -- AAGUID is always 16 bytes per the WebAuthn spec. The CHECK
    -- constraint catches schema drift / manual edits at write time so
    -- the row_to_credential reader does not need to guess what a
    -- short value means.
    aaguid          BLOB NOT NULL CHECK (length(aaguid) = 16),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"#;

struct Store {
    conn: Connection,
}

impl Store {
    fn open<P: AsRef<Path>>(path: P) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Get or create the demo user. Returns the user_handle bytes.
    fn ensure_user(&self) -> rusqlite::Result<Vec<u8>> {
        let mut q = self
            .conn
            .prepare("SELECT id FROM users WHERE username = ?1")?;
        let mut rows = q.query(params![USERNAME])?;
        if let Some(row) = rows.next()? {
            return row.get::<_, Vec<u8>>(0);
        }
        drop(rows);
        drop(q);
        // First run: mint a fresh user_handle.
        let handle = {
            use rand::RngCore;
            let mut buf = vec![0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        };
        self.conn.execute(
            "INSERT INTO users (id, username) VALUES (?1, ?2)",
            params![handle, USERNAME],
        )?;
        Ok(handle)
    }

    fn insert_credential(&self, user_id: &[u8], cred: &PasskeyCredential) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO credentials (id, user_id, public_key_cose, counter, transports, aaguid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                cred.id.as_bytes(),
                user_id,
                cred.public_key_cose.as_bytes(),
                cred.counter,
                cred.transports.join(","),
                cred.aaguid,
            ],
        )?;
        Ok(())
    }

    fn list_credentials(&self, user_id: &[u8]) -> rusqlite::Result<Vec<PasskeyCredential>> {
        let mut q = self.conn.prepare(
            "SELECT id, public_key_cose, counter, transports, aaguid
             FROM credentials WHERE user_id = ?1",
        )?;
        let creds = q
            .query_map(params![user_id], row_to_credential)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(creds)
    }

    fn find_credential(&self, cred_id: &[u8]) -> rusqlite::Result<Option<PasskeyCredential>> {
        let mut q = self.conn.prepare(
            "SELECT id, public_key_cose, counter, transports, aaguid
             FROM credentials WHERE id = ?1",
        )?;
        let mut rows = q.query(params![cred_id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(row_to_credential(row)?));
        }
        Ok(None)
    }

    fn update_counter(&self, cred_id: &[u8], counter: u32) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE credentials SET counter = ?1 WHERE id = ?2",
            params![counter, cred_id],
        )?;
        Ok(())
    }
}

fn row_to_credential(row: &rusqlite::Row<'_>) -> rusqlite::Result<PasskeyCredential> {
    let id: Vec<u8> = row.get(0)?;
    let pkc: Vec<u8> = row.get(1)?;
    let counter: u32 = row.get(2)?;
    let transports_csv: String = row.get(3)?;
    let aaguid_vec: Vec<u8> = row.get(4)?;

    // The aaguid column is always 16 bytes. A row with a different
    // length means schema drift or a manually-edited DB - error rather
    // than silently zeroing it out, because [0u8; 16] is ALSO the
    // legitimate "no attestation, real AAGUID is all zeros" value
    // and conflating the two would let a corrupted row impersonate a
    // valid no-attestation credential.
    if aaguid_vec.len() != 16 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Blob,
            format!(
                "aaguid column wrong length: expected 16 bytes, got {}",
                aaguid_vec.len()
            )
            .into(),
        ));
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&aaguid_vec);

    Ok(PasskeyCredential {
        id: CredentialId(id),
        public_key_cose: CosePublicKey(pkc),
        counter,
        transports: if transports_csv.is_empty() {
            Vec::new()
        } else {
            transports_csv.split(',').map(|s| s.to_owned()).collect()
        },
        aaguid,
    })
}

// ---------- in-memory ceremony state --------------------------------------

#[derive(Default)]
struct Session {
    reg_state: Option<RegistrationState>,
    auth_state: Option<AuthenticationState>,
}

struct AppState {
    store: Mutex<Store>,
    sessions: Mutex<HashMap<String, Session>>,
    wa: Webauthn,
}

// ---------- handlers ------------------------------------------------------

async fn register_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_or_create_sid(&cookies);
    let store = state.store.lock().await;
    let user_handle = store.ensure_user().map_err(db_err)?;
    let existing: Vec<_> = store
        .list_credentials(&user_handle)
        .map_err(db_err)?
        .into_iter()
        .map(|c| c.id)
        .collect();
    drop(store);

    let (challenge, reg_state) =
        state
            .wa
            .start_registration(&user_handle, USERNAME, "Alice", &existing);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .reg_state = Some(reg_state);

    Ok(json_with_sid(&challenge, &sid))
}

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

    let store = state.store.lock().await;
    let user_handle = store.ensure_user().map_err(db_err)?;
    store
        .insert_credential(&user_handle, &credential)
        .map_err(db_err)?;

    Ok(Json(RegisterFinishReply {
        ok: true,
        credential_id: credential.id.to_b64url(),
    }))
}

#[derive(Serialize)]
struct RegisterFinishReply {
    ok: bool,
    credential_id: String,
}

async fn authenticate_start(
    State(state): State<Arc<AppState>>,
    cookies: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_or_create_sid(&cookies);

    let store = state.store.lock().await;
    let user_handle = store.ensure_user().map_err(db_err)?;
    let creds = store.list_credentials(&user_handle).map_err(db_err)?;
    drop(store);
    if creds.is_empty() {
        return Err(AppError::BadRequest(
            "no registered credentials - register first",
        ));
    }

    // Use the for_user variant so finish_authentication can verify
    // the assertion's userHandle matches THIS user (WebAuthn-3 §7.2
    // step 6) — defence in depth against credential-id collisions in
    // a multi-user store.
    let (challenge, auth_state) = state
        .wa
        .start_authentication_with_creds_for_user(&user_handle, &creds);

    state
        .sessions
        .lock()
        .await
        .entry(sid.clone())
        .or_default()
        .auth_state = Some(auth_state);

    Ok(json_with_sid(&challenge, &sid))
}

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

    let asserted_id = CredentialId::from_b64url(&body.id)
        .map_err(|_| AppError::BadRequest("bad credential id"))?;
    let store = state.store.lock().await;
    let mut stored = store
        .find_credential(asserted_id.as_bytes())
        .map_err(db_err)?
        .ok_or(AppError::Unauthorized("unknown credential".into()))?;

    let outcome = state
        .wa
        .finish_authentication(&auth_state, &body, &stored)
        .map_err(|e| AppError::Unauthorized(format!("auth verify failed: {e}")))?;

    // Persist the new counter. Important: do this BEFORE replying so a
    // crash between verify and reply still leaves the counter advanced;
    // the next assertion will be rejected as replay rather than reused.
    store
        .update_counter(stored.id.as_bytes(), outcome.new_counter)
        .map_err(db_err)?;
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

fn get_or_create_sid(cookies: &HeaderMap) -> String {
    sid_from_cookies(cookies).unwrap_or_else(|| {
        use rand::RngCore;
        let mut buf = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut buf);
        hex::encode(buf)
    })
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

#[derive(Debug)]
enum AppError {
    BadRequest(&'static str),
    Unauthorized(String),
    Db(String),
}

fn db_err(e: rusqlite::Error) -> AppError {
    AppError::Db(e.to_string())
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m.to_owned()),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            Self::Db(m) => (StatusCode::INTERNAL_SERVER_ERROR, format!("db: {m}")),
        };
        (code, msg).into_response()
    }
}

// ---------- main ----------------------------------------------------------

#[tokio::main]
async fn main() {
    let store = Store::open(DB_PATH).expect("open SQLite");
    println!("opened SQLite at {DB_PATH}");
    let wa = Webauthn::new("localhost", "Passkey sqlite demo", "http://localhost:3000")
        .authenticator_attachment(Attachment::Any)
        .require_user_verification(false);

    let state = Arc::new(AppState {
        store: Mutex::new(store),
        sessions: Mutex::new(HashMap::new()),
        wa,
    });

    let app = Router::new()
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        .route("/authenticate/start", post(authenticate_start))
        .route("/authenticate/finish", post(authenticate_finish))
        // Reuses the single-user HTML from the original axum_server example.
        .fallback_service(ServeDir::new("examples/static"))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("sqlite demo listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
