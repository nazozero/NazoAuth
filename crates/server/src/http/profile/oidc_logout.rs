//! OIDC RP-Initiated Logout and Back-Channel Logout support.
//! The endpoint clears the OP browser session locally and persists
//! Back-Channel Logout notifications in an outbox before returning.

use crate::http::prelude::*;
use actix_web::web::Payload;
use std::time::Duration as StdDuration;

const BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS: i64 = 120;
const BACKCHANNEL_LOGOUT_DELIVERY_BATCH_SIZE: i64 = 20;
const BACKCHANNEL_LOGOUT_LOCK_TIMEOUT_SECONDS: i64 = 300;
const BACKCHANNEL_LOGOUT_ERROR_MAX_CHARS: usize = 512;

#[derive(Default)]
struct LogoutRequest {
    id_token_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Clone, Debug)]
struct BackchannelLogoutClient {
    id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    redirect_uris: Value,
    post_logout_redirect_uris: Value,
    backchannel_logout_uri: Option<String>,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: bool,
    subject_type: String,
    sector_identifier_host: Option<String>,
}

#[derive(Clone, Debug)]
struct FrontchannelLogoutClient {
    client_id: String,
    frontchannel_logout_uri: String,
    frontchannel_logout_session_required: bool,
}

type BackchannelLogoutDelivery = nazo_auth::BackchannelLogoutDelivery;

pub(crate) async fn oidc_logout(
    state: Data<AppState>,
    req: HttpRequest,
    mut payload: Payload,
) -> HttpResponse {
    let form = match parse_logout_request(&req, &mut payload).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let session_cookie = cookie_value(&req, &state.settings.session_cookie_name);
    let current_session = match current_session(&state, &req).await {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(%error, "failed to resolve session for oidc logout");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "logout session lookup failed.",
            );
        }
    };
    let hint = form
        .id_token_hint
        .as_deref()
        .and_then(|token| decode_id_token_hint(&state, token));
    if form.id_token_hint.is_some() && hint.is_none() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "id_token_hint is invalid.",
        );
    }

    let client_id = match identify_logout_client(&form, hint.as_ref()) {
        Ok(client_id) => client_id,
        Err(response) => return response,
    };
    let client = match lookup_logout_client(&state, client_id.as_deref()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let redirect = match validate_post_logout_redirect(&form, client.as_ref()) {
        Ok(redirect) => redirect,
        Err(response) => return response,
    };
    if current_session.as_ref().is_some_and(|session| {
        !logout_request_authorizes_session_clear(
            &state.settings,
            &state,
            &req,
            session,
            hint.as_ref(),
            client.as_ref(),
        )
    }) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "logout request is not authorized for the current OP session.",
        );
    }

    let frontchannel_urls = if state.settings.enable_frontchannel_logout {
        if let Some(session) = current_session.as_ref() {
            let clients = if let Some(client) = client.as_ref() {
                frontchannel_logout_client_for_logout_client(client)
                    .into_iter()
                    .collect::<Vec<_>>()
            } else {
                match frontchannel_logout_clients_for_user(&state, session.user.id()).await {
                    Ok(clients) => clients,
                    Err(error) => {
                        tracing::warn!(%error, "failed to query front-channel logout clients");
                        Vec::new()
                    }
                }
            };
            clients
                .into_iter()
                .filter_map(|client| {
                    frontchannel_logout_url(&client, &state.settings.issuer, &session.oidc_sid)
                        .map_err(|error| {
                            tracing::warn!(
                                %error,
                                client_id = %client.client_id,
                                "failed to compose front-channel logout URI"
                            );
                        })
                        .ok()
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    if let Some(session) = current_session.as_ref()
        && let Err(error) =
            enqueue_backchannel_logout(&state, session, hint.as_ref(), client.as_ref()).await
    {
        tracing::warn!(%error, "failed to persist back-channel logout deliveries");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "back-channel logout persistence failed.",
        );
    }

    if let Some(session_id) = session_cookie {
        let _ = nazo_valkey::SessionStore::new(&state.valkey_connection())
            .delete(&session_id)
            .await;
    }

    audit_event(
        "oidc_logout",
        audit_fields(&[
            (
                "client_id",
                json!(client.as_ref().map(|client| &client.client_id)),
            ),
            (
                "subject_hash",
                json!(
                    current_session
                        .as_ref()
                        .map(|session| blake3_hex(&session.user.id().to_string()))
                ),
            ),
        ]),
    );

    let response = if frontchannel_urls.is_empty() {
        match redirect {
            Some(location) => redirect_found(location),
            None => json_response_no_store(json!({"success": true})),
        }
    } else {
        HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .insert_header((header::PRAGMA, "no-cache"))
            .content_type("text/html; charset=utf-8")
            .body(frontchannel_logout_document(
                &frontchannel_urls,
                redirect.as_deref(),
            ))
    };
    with_cookie_headers(
        response,
        &[
            clear_cookie(
                &state.settings.session_cookie_name,
                state.settings.cookie_secure,
            ),
            clear_cookie(
                &state.settings.csrf_cookie_name,
                state.settings.cookie_secure,
            ),
        ],
    )
}

fn frontchannel_logout_url(
    client: &FrontchannelLogoutClient,
    issuer: &str,
    oidc_sid: &str,
) -> anyhow::Result<String> {
    let mut url = url::Url::parse(&client.frontchannel_logout_uri)?;
    if client.frontchannel_logout_session_required {
        url.query_pairs_mut()
            .append_pair("iss", issuer)
            .append_pair("sid", oidc_sid);
    }
    Ok(url.to_string())
}

fn frontchannel_logout_document(frontchannel_urls: &[String], redirect: Option<&str>) -> String {
    let iframe_count = frontchannel_urls.len();
    let iframe_onload = if redirect.is_some() {
        " onload=\"nazoFrontchannelLogoutFrameDone()\""
    } else {
        ""
    };
    let iframes = frontchannel_urls
        .iter()
        .map(|url| {
            format!(
                "<iframe title=\"OIDC Front-Channel Logout\" src=\"{}\"{}></iframe>",
                escape_html_attribute(url),
                iframe_onload
            )
        })
        .collect::<String>();
    let redirect_script = redirect.map_or_else(String::new, |location| {
        format!(
            concat!(
                "<script>",
                "(function(){{",
                "var remaining={iframe_count};",
                "var redirected=false;",
                "function finish(){{",
                "if(redirected){{return;}}",
                "redirected=true;",
                "window.location.replace('{location}');",
                "}}",
                "window.nazoFrontchannelLogoutFrameDone=function(){{",
                "remaining-=1;",
                "if(remaining<=0){{setTimeout(finish,50);}}",
                "}};",
                "setTimeout(finish,2500);",
                "}})();",
                "</script>"
            ),
            iframe_count = iframe_count,
            location = escape_js_string(location)
        )
    });
    format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\">",
            "<meta http-equiv=\"cache-control\" content=\"no-store\">",
            "<style>iframe{{display:none;width:0;height:0;border:0}}</style>",
            "</head><body>{redirect_script}{iframes}</body></html>"
        ),
        iframes = iframes,
        redirect_script = redirect_script
    )
}

fn escape_html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_js_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

async fn parse_logout_request(
    req: &HttpRequest,
    payload: &mut Payload,
) -> Result<LogoutRequest, HttpResponse> {
    let mut form = parse_logout_pairs(req.query_string())?;
    if req.method() == actix_web::http::Method::POST {
        if !request_uses_form_urlencoded(req) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "logout POST must use application/x-www-form-urlencoded.",
            ));
        }
        let mut body = Bytes::new();
        while let Some(chunk) = payload.next().await {
            let chunk = chunk.map_err(|_| {
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "logout request body is invalid.",
                )
            })?;
            if body.len().saturating_add(chunk.len()) > 16 * 1024 {
                return Err(oauth_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "logout request body is too large.",
                ));
            }
            let mut combined = Vec::with_capacity(body.len() + chunk.len());
            combined.extend_from_slice(&body);
            combined.extend_from_slice(&chunk);
            body = Bytes::from(combined);
        }
        merge_logout_pairs(&mut form, &body)?;
    }
    Ok(form)
}

fn parse_logout_pairs(raw: &str) -> Result<LogoutRequest, HttpResponse> {
    let mut form = LogoutRequest::default();
    merge_logout_pairs(&mut form, raw.as_bytes())?;
    Ok(form)
}

fn merge_logout_pairs(form: &mut LogoutRequest, raw: &[u8]) -> Result<(), HttpResponse> {
    for (key, value) in url::form_urlencoded::parse(raw) {
        let value = value.trim();
        match key.as_ref() {
            "id_token_hint" => set_once(&mut form.id_token_hint, value)?,
            "client_id" => set_once(&mut form.client_id, value)?,
            "post_logout_redirect_uri" => set_once(&mut form.post_logout_redirect_uri, value)?,
            "state" => set_once(&mut form.state, value)?,
            _ => {}
        }
    }
    Ok(())
}

fn set_once(field: &mut Option<String>, value: &str) -> Result<(), HttpResponse> {
    if field.is_some() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "duplicate logout parameter.",
        ));
    }
    field.replace(value.to_owned());
    Ok(())
}

fn logout_request_authorizes_session_clear(
    settings: &Settings,
    state: &AppState,
    req: &HttpRequest,
    session: &CurrentSession,
    hint: Option<&IdTokenHintClaims>,
    client: Option<&BackchannelLogoutClient>,
) -> bool {
    has_valid_csrf_token(state, req, None)
        || hint.is_some_and(|hint| {
            id_token_hint_matches_current_session(
                settings,
                client,
                session.user.id(),
                &session.oidc_sid,
                hint,
            )
        })
}

#[derive(Deserialize)]
struct IdTokenHintClaims {
    sub: String,
    aud: Value,
    #[serde(default)]
    sid: Option<String>,
}

fn decode_id_token_hint(state: &AppState, token: &str) -> Option<IdTokenHintClaims> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.typ.as_deref().is_some_and(|typ| typ != "JWT")
        || signing_algorithm_name(header.alg).is_none()
    {
        return None;
    }
    let keyset = state.keyset.snapshot();
    let verification_key = keyset.verification_key(header.kid.as_deref()?)?;
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[state.settings.issuer.as_str()]);
    jsonwebtoken::decode::<IdTokenHintClaims>(token, &decoding_key, &validation)
        .ok()
        .map(|data| data.claims)
}

fn identify_logout_client(
    form: &LogoutRequest,
    hint: Option<&IdTokenHintClaims>,
) -> Result<Option<String>, HttpResponse> {
    match (form.client_id.as_deref(), hint) {
        (Some(client_id), Some(hint)) if !audience_contains(&hint.aud, client_id) => {
            Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id does not match id_token_hint audience.",
            ))
        }
        (Some(client_id), _) => Ok(Some(client_id.to_owned())),
        (None, Some(hint)) => single_audience(&hint.aud).map(Some).ok_or_else(|| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required when id_token_hint has multiple audiences.",
            )
        }),
        (None, None) if form.post_logout_redirect_uri.is_some() => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id or id_token_hint is required with post_logout_redirect_uri.",
        )),
        (None, None) => Ok(None),
    }
}

fn audience_contains(aud: &Value, client_id: &str) -> bool {
    match aud {
        Value::String(value) => value == client_id,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
}

fn single_audience(aud: &Value) -> Option<String> {
    match aud {
        Value::String(value) => Some(value.clone()),
        Value::Array(values) => {
            let audiences = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .take(2)
                .collect::<Vec<_>>();
            match audiences.as_slice() {
                [audience] => Some(audience.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}

async fn lookup_logout_client(
    state: &AppState,
    client_id: Option<&str>,
) -> Result<Option<BackchannelLogoutClient>, HttpResponse> {
    let Some(client_id) = client_id else {
        return Ok(None);
    };
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .by_client_id(DEFAULT_TENANT_ID, client_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query oidc logout client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "logout client lookup failed.",
            )
        })
        .and_then(|client| {
            client.filter(|client| client.is_active).map_or_else(
                || {
                    Err(oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "logout client is not registered or active.",
                    ))
                },
                |client| Ok(Some(logout_client(client))),
            )
        })
}

fn validate_post_logout_redirect(
    form: &LogoutRequest,
    client: Option<&BackchannelLogoutClient>,
) -> Result<Option<String>, HttpResponse> {
    let Some(uri) = form.post_logout_redirect_uri.as_deref() else {
        return Ok(None);
    };
    let Some(client) = client else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "post_logout_redirect_uri requires a registered client.",
        ));
    };
    if !json_array_to_strings(&client.post_logout_redirect_uris)
        .iter()
        .any(|registered| registered == uri)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "post_logout_redirect_uri is not registered.",
        ));
    }
    let mut url = url::Url::parse(uri).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "post_logout_redirect_uri is invalid.",
        )
    })?;
    if let Some(state) = form.state.as_deref().filter(|state| !state.is_empty()) {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(Some(url.into()))
}

async fn enqueue_backchannel_logout(
    state: &AppState,
    session: &CurrentSession,
    hint: Option<&IdTokenHintClaims>,
    hinted_client: Option<&BackchannelLogoutClient>,
) -> anyhow::Result<()> {
    if let Some(hint) = hint
        && !id_token_hint_matches_current_session(
            &state.settings,
            hinted_client,
            session.user.id(),
            &session.oidc_sid,
            hint,
        )
    {
        tracing::warn!("id_token_hint subject or sid did not match the current OP session");
        return Ok(());
    }
    let clients = match backchannel_logout_clients_for_user(state, session.user.id()).await {
        Ok(mut clients) => {
            if let Some(client) = hinted_client
                && !clients
                    .iter()
                    .any(|candidate| candidate.client_id == client.client_id)
            {
                clients.push(client.clone());
            }
            clients
        }
        Err(error) => return Err(error),
    };
    for client in clients {
        let Some(uri) = client.backchannel_logout_uri.clone() else {
            continue;
        };
        let subject =
            match unique_logout_subject_for_client(&state.settings, session.user.id(), &client) {
                Ok(subject) => subject,
                Err(_) => continue,
            };
        let token = match make_backchannel_logout_token(
            state,
            BackchannelLogoutTokenInput {
                client_id: &client.client_id,
                subject: subject.as_deref(),
                sid: Some(session.oidc_sid.as_str()),
                ttl: BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS,
            },
        )
        .await
        {
            Ok(token) => token,
            Err(error) => return Err(error.into()),
        };
        persist_backchannel_logout_delivery(
            state,
            &client,
            &uri,
            &token,
            Utc::now() + Duration::seconds(BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS),
        )
        .await?;
    }
    Ok(())
}

async fn backchannel_logout_clients_for_user(
    state: &AppState,
    user_id: Uuid,
) -> anyhow::Result<Vec<BackchannelLogoutClient>> {
    Ok(
        nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
            .active_for_user(user_id)
            .await?
            .into_iter()
            .filter(|client| client.backchannel_logout_uri.is_some())
            .map(logout_client)
            .collect(),
    )
}

async fn frontchannel_logout_clients_for_user(
    state: &AppState,
    user_id: Uuid,
) -> anyhow::Result<Vec<FrontchannelLogoutClient>> {
    Ok(
        nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
            .active_for_user(user_id)
            .await?
            .into_iter()
            .filter_map(|client| {
                Some(FrontchannelLogoutClient {
                    client_id: client.client_id.clone(),
                    frontchannel_logout_uri: client.frontchannel_logout_uri.clone()?,
                    frontchannel_logout_session_required: client
                        .frontchannel_logout_session_required,
                })
            })
            .collect(),
    )
}

fn logout_client(client: ClientRow) -> BackchannelLogoutClient {
    BackchannelLogoutClient {
        id: client.id,
        tenant_id: client.tenant_id,
        client_id: client.client_id.clone(),
        redirect_uris: json!(&client.redirect_uris),
        post_logout_redirect_uris: json!(&client.post_logout_redirect_uris),
        backchannel_logout_uri: client.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: client.frontchannel_logout_uri.clone(),
        frontchannel_logout_session_required: client.frontchannel_logout_session_required,
        subject_type: client.subject_type.clone(),
        sector_identifier_host: client.sector_identifier_host.clone(),
    }
}

fn frontchannel_logout_client_for_logout_client(
    client: &BackchannelLogoutClient,
) -> Option<FrontchannelLogoutClient> {
    client
        .frontchannel_logout_uri
        .as_ref()
        .map(|frontchannel_logout_uri| FrontchannelLogoutClient {
            client_id: client.client_id.clone(),
            frontchannel_logout_uri: frontchannel_logout_uri.clone(),
            frontchannel_logout_session_required: client.frontchannel_logout_session_required,
        })
}

fn id_token_hint_matches_current_session(
    settings: &Settings,
    client: Option<&BackchannelLogoutClient>,
    user_id: Uuid,
    oidc_sid: &str,
    hint: &IdTokenHintClaims,
) -> bool {
    if hint
        .sid
        .as_deref()
        .is_some_and(|hint_sid| hint_sid != oidc_sid)
    {
        return false;
    }
    client.is_some_and(|client| {
        logout_subjects_for_client(settings, user_id, client)
            .is_ok_and(|subjects| subjects.iter().any(|subject| subject == &hint.sub))
    })
}

fn unique_logout_subject_for_client(
    settings: &Settings,
    user_id: Uuid,
    client: &BackchannelLogoutClient,
) -> anyhow::Result<Option<String>> {
    let subjects = logout_subjects_for_client(settings, user_id, client)?;
    match subjects.as_slice() {
        [subject] => Ok(Some(subject.clone())),
        _ => Ok(None),
    }
}

fn logout_subjects_for_client(
    settings: &Settings,
    user_id: Uuid,
    client: &BackchannelLogoutClient,
) -> anyhow::Result<Vec<String>> {
    let mut redirect_uris = json_array_to_strings(&client.redirect_uris);
    if redirect_uris.is_empty() {
        redirect_uris.push(String::new());
    }
    let sector_host = client.sector_identifier_host.as_deref();
    let subject_type = client.subject_type.as_str();
    let mut subjects = Vec::with_capacity(redirect_uris.len());
    for redirect_uri in redirect_uris {
        let redirect_uri = redirect_uri.as_str();
        let subject =
            compute_subject_for_client(settings, user_id, subject_type, sector_host, redirect_uri)?;
        subjects.push(subject);
    }
    subjects.sort();
    subjects.dedup();
    Ok(subjects)
}

async fn post_backchannel_logout(uri: &str, token: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("logout_token", token)
        .finish();
    let response = client
        .post(uri)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("backchannel logout endpoint returned {}", response.status());
    }
    Ok(())
}

async fn persist_backchannel_logout_delivery(
    state: &AppState,
    client: &BackchannelLogoutClient,
    uri: &str,
    token: &str,
    expires_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    nazo_postgres::AuditRepository::new(state.diesel_db.clone())
        .enqueue_backchannel_logout(
            client.tenant_id,
            client.id,
            &client.client_id,
            uri,
            token,
            expires_at,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to enqueue backchannel logout: {error}"))
}

fn backchannel_logout_next_retry_at(
    attempt_index: i32,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let delay_seconds = match attempt_index {
        0 => 5,
        1 => 15,
        2 => 45,
        _ => return None,
    };
    let next_attempt_at = now + Duration::seconds(delay_seconds);
    (next_attempt_at < expires_at).then_some(next_attempt_at)
}

async fn claim_due_backchannel_logout_deliveries(
    state: &AppState,
    limit: i64,
) -> anyhow::Result<Vec<BackchannelLogoutDelivery>> {
    nazo_postgres::AuditRepository::new(state.diesel_db.clone())
        .claim_due_backchannel_logout(limit, BACKCHANNEL_LOGOUT_LOCK_TIMEOUT_SECONDS as i32)
        .await
        .map_err(|error| anyhow::anyhow!("failed to claim backchannel logout: {error}"))
}

async fn mark_backchannel_logout_delivery_success(
    state: &AppState,
    delivery: &BackchannelLogoutDelivery,
) -> anyhow::Result<()> {
    nazo_postgres::AuditRepository::new(state.diesel_db.clone())
        .complete_backchannel_logout(delivery.id, delivery.attempts)
        .await
        .map_err(|error| anyhow::anyhow!("failed to complete backchannel logout: {error}"))
}

async fn mark_backchannel_logout_delivery_failure(
    state: &AppState,
    delivery: &BackchannelLogoutDelivery,
    error: &str,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let last_error = truncate_backchannel_logout_error(error);
    let next_attempt_at =
        backchannel_logout_next_retry_at(delivery.attempts - 1, now, delivery.expires_at);
    nazo_postgres::AuditRepository::new(state.diesel_db.clone())
        .fail_backchannel_logout(delivery.id, delivery.attempts, next_attempt_at, &last_error)
        .await
        .map_err(|error| anyhow::anyhow!("failed to update backchannel logout: {error}"))
}

fn truncate_backchannel_logout_error(error: &str) -> String {
    error
        .chars()
        .take(BACKCHANNEL_LOGOUT_ERROR_MAX_CHARS)
        .collect()
}

pub(crate) async fn process_backchannel_logout_delivery_batch(
    state: &AppState,
) -> anyhow::Result<usize> {
    let deliveries =
        claim_due_backchannel_logout_deliveries(state, BACKCHANNEL_LOGOUT_DELIVERY_BATCH_SIZE)
            .await?;
    let processed = deliveries.len();
    for delivery in deliveries {
        match post_backchannel_logout(&delivery.logout_uri, &delivery.logout_token).await {
            Ok(()) => mark_backchannel_logout_delivery_success(state, &delivery).await?,
            Err(error) => {
                let error_message = error.to_string();
                tracing::warn!(
                    error = %error_message,
                    backchannel_logout_uri = %delivery.logout_uri,
                    "backchannel logout delivery failed"
                );
                mark_backchannel_logout_delivery_failure(state, &delivery, &error_message).await?;
            }
        }
    }
    Ok(processed)
}

pub(crate) fn spawn_backchannel_logout_delivery_worker(state: Data<AppState>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = process_backchannel_logout_delivery_batch(&state).await {
                let error_message = error.to_string();
                tracing::warn!(
                    error = %error_message,
                    "back-channel logout delivery worker failed"
                );
            }
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/oidc_logout.rs"]
mod tests;
