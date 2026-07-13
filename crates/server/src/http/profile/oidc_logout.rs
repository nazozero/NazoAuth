//! OIDC RP-Initiated Logout and Back-Channel Logout support.
//! The endpoint clears the OP browser session locally and persists
//! Back-Channel Logout notifications in an outbox before returning.
use nazo_http_actix::{
    json_response_no_store, oauth_error, redirect_found, request_uses_form_urlencoded,
};

use crate::domain::{ClientRow, OidcLogoutHandles};
use crate::support::{CurrentSession, DEFAULT_TENANT_ID, audit_event, audit_fields, blake3_hex};
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::web::Payload;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Duration, Utc};
use futures_util::StreamExt;
use nazo_http_actix::{clear_cookie, with_cookie_headers};
use serde_json::{Value, json};
#[cfg(not(test))]
use std::time::Duration as StdDuration;
use uuid::Uuid;

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
    handles: Data<OidcLogoutHandles>,
    req: HttpRequest,
    mut payload: Payload,
) -> HttpResponse {
    oidc_logout_with_handles(handles.get_ref(), req, &mut payload).await
}

async fn oidc_logout_with_handles(
    handles: &OidcLogoutHandles,
    req: HttpRequest,
    payload: &mut Payload,
) -> HttpResponse {
    let form = match parse_logout_request(&req, payload).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let current_session = match handles.current_session(&req).await {
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
        .and_then(|token| handles.decode_id_token_hint(token));
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
    let client = match lookup_logout_client_with_handles(handles, client_id.as_deref()).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let redirect = match validate_post_logout_redirect(&form, client.as_ref()) {
        Ok(redirect) => redirect,
        Err(response) => return response,
    };
    if current_session.as_ref().is_some_and(|session| {
        !logout_request_authorizes_session_clear(
            handles,
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

    let frontchannel_urls = if handles.permits_existing_frontchannel_transaction() {
        if let Some(session) = current_session.as_ref() {
            let clients = if let Some(client) = client.as_ref() {
                frontchannel_logout_client_for_logout_client(client)
                    .into_iter()
                    .collect::<Vec<_>>()
            } else {
                match frontchannel_logout_clients_for_user(handles, session.user.id()).await {
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
                    frontchannel_logout_url(&client, handles.issuer(), &session.oidc_sid)
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
            enqueue_backchannel_logout(handles, session, hint.as_ref(), client.as_ref()).await
    {
        tracing::warn!(%error, "failed to persist back-channel logout deliveries");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "back-channel logout persistence failed.",
        );
    }

    let _ = handles.delete_request_session(&req).await;

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
                handles.http_config().session_cookie_name(),
                handles.http_config().cookie_secure(),
            ),
            clear_cookie(
                handles.http_config().csrf_cookie_name(),
                handles.http_config().cookie_secure(),
            ),
        ],
    )
}

fn frontchannel_logout_url(
    client: &FrontchannelLogoutClient,
    issuer: &str,
    oidc_sid: &str,
) -> anyhow::Result<String> {
    nazo_auth::frontchannel_logout_url(
        &client.frontchannel_logout_uri,
        client.frontchannel_logout_session_required,
        issuer,
        oidc_sid,
    )
    .map_err(Into::into)
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
    handles: &OidcLogoutHandles,
    req: &HttpRequest,
    session: &CurrentSession,
    hint: Option<&IdTokenHintClaims>,
    client: Option<&BackchannelLogoutClient>,
) -> bool {
    handles.has_valid_csrf_token(req)
        || hint.is_some_and(|hint| {
            id_token_hint_matches_current_session_with_policy(
                handles.issuer(),
                handles.pairwise_subject_secret(),
                client,
                session.user.id(),
                &session.oidc_sid,
                hint,
            )
        })
}

type IdTokenHintClaims = nazo_auth::IdTokenHintClaims;

fn identify_logout_client(
    form: &LogoutRequest,
    hint: Option<&IdTokenHintClaims>,
) -> Result<Option<String>, HttpResponse> {
    nazo_auth::resolve_logout_client_id(
        form.client_id.as_deref(),
        form.post_logout_redirect_uri.is_some(),
        hint,
    )
    .map_err(logout_policy_error_response)
}

#[cfg(test)]
fn audience_contains(aud: &Value, client_id: &str) -> bool {
    nazo_auth::audience_contains(aud, client_id)
}

#[cfg(test)]
fn single_audience(aud: &Value) -> Option<String> {
    nazo_auth::single_audience(aud)
}

async fn lookup_logout_client_with_handles(
    handles: &OidcLogoutHandles,
    client_id: Option<&str>,
) -> Result<Option<BackchannelLogoutClient>, HttpResponse> {
    let Some(client_id) = client_id else {
        return Ok(None);
    };
    handles
        .logout_client(client_id, DEFAULT_TENANT_ID)
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
    let registered = client.map(|client| json_value_strings(&client.post_logout_redirect_uris));
    nazo_auth::validate_post_logout_redirect(
        form.post_logout_redirect_uri.as_deref(),
        form.state.as_deref(),
        registered.as_deref(),
    )
    .map_err(logout_policy_error_response)
}

fn logout_policy_error_response(error: nazo_auth::LogoutPolicyError) -> HttpResponse {
    let description = match error {
        nazo_auth::LogoutPolicyError::ClientAudienceMismatch => {
            "client_id does not match id_token_hint audience."
        }
        nazo_auth::LogoutPolicyError::AmbiguousAudience => {
            "client_id is required when id_token_hint has multiple audiences."
        }
        nazo_auth::LogoutPolicyError::ClientRequiredForRedirect => {
            "client_id or id_token_hint is required with post_logout_redirect_uri."
        }
        nazo_auth::LogoutPolicyError::RegisteredClientRequired => {
            "post_logout_redirect_uri requires a registered client."
        }
        nazo_auth::LogoutPolicyError::UnregisteredRedirect => {
            "post_logout_redirect_uri is not registered."
        }
        nazo_auth::LogoutPolicyError::InvalidRedirect => "post_logout_redirect_uri is invalid.",
        nazo_auth::LogoutPolicyError::PairwiseSecretMissing
        | nazo_auth::LogoutPolicyError::UnsupportedSubjectType => "logout subject policy failed.",
    };
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description)
}

async fn enqueue_backchannel_logout(
    handles: &OidcLogoutHandles,
    session: &CurrentSession,
    hint: Option<&IdTokenHintClaims>,
    hinted_client: Option<&BackchannelLogoutClient>,
) -> anyhow::Result<()> {
    if let Some(hint) = hint
        && !id_token_hint_matches_current_session_with_policy(
            handles.issuer(),
            handles.pairwise_subject_secret(),
            hinted_client,
            session.user.id(),
            &session.oidc_sid,
            hint,
        )
    {
        tracing::warn!("id_token_hint subject or sid did not match the current OP session");
        return Ok(());
    }
    let clients = match backchannel_logout_clients_for_user(handles, session.user.id()).await {
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
    let mut deliveries = Vec::new();
    for client in clients {
        let Some(uri) = client.backchannel_logout_uri.clone() else {
            continue;
        };
        let subject = match unique_logout_subject_for_client_with_policy(
            handles.issuer(),
            handles.pairwise_subject_secret(),
            session.user.id(),
            &client,
        ) {
            Ok(subject) => subject,
            Err(_) => continue,
        };
        let token = match handles
            .sign_backchannel_logout_token(
                &client.client_id,
                subject.as_deref(),
                Some(session.oidc_sid.as_str()),
                BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS,
            )
            .await
        {
            Ok(token) => token,
            Err(error) => return Err(error.into()),
        };
        deliveries.push(nazo_auth::PendingBackchannelLogoutDelivery {
            tenant_id: client.tenant_id,
            client_id: client.id,
            client_public_id: client.client_id,
            logout_uri: uri,
            logout_token: token,
            expires_at: Utc::now() + Duration::seconds(BACKCHANNEL_LOGOUT_TOKEN_TTL_SECONDS),
        });
    }
    handles
        .enqueue_backchannel_logout_batch(&deliveries)
        .await
        .map_err(|error| anyhow::anyhow!("failed to enqueue backchannel logout: {error}"))
}

async fn backchannel_logout_clients_for_user(
    handles: &OidcLogoutHandles,
    user_id: Uuid,
) -> anyhow::Result<Vec<BackchannelLogoutClient>> {
    Ok(handles
        .active_clients_for_user(user_id)
        .await?
        .into_iter()
        .filter(|client| client.backchannel_logout_uri.is_some())
        .map(logout_client)
        .collect())
}

async fn frontchannel_logout_clients_for_user(
    handles: &OidcLogoutHandles,
    user_id: Uuid,
) -> anyhow::Result<Vec<FrontchannelLogoutClient>> {
    Ok(handles
        .active_clients_for_user(user_id)
        .await?
        .into_iter()
        .filter_map(|client| {
            Some(FrontchannelLogoutClient {
                client_id: client.client_id.clone(),
                frontchannel_logout_uri: client.frontchannel_logout_uri.clone()?,
                frontchannel_logout_session_required: client.frontchannel_logout_session_required,
            })
        })
        .collect())
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

fn id_token_hint_matches_current_session_with_policy(
    issuer: &str,
    pairwise_subject_secret: Option<&str>,
    client: Option<&BackchannelLogoutClient>,
    user_id: Uuid,
    oidc_sid: &str,
    hint: &IdTokenHintClaims,
) -> bool {
    let client = client.map(protocol_logout_client);
    nazo_auth::id_token_hint_matches_session(
        issuer,
        pairwise_subject_secret,
        client.as_ref(),
        user_id,
        oidc_sid,
        hint,
    )
}

fn unique_logout_subject_for_client_with_policy(
    issuer: &str,
    pairwise_subject_secret: Option<&str>,
    user_id: Uuid,
    client: &BackchannelLogoutClient,
) -> anyhow::Result<Option<String>> {
    nazo_auth::unique_logout_subject_for_client(
        issuer,
        pairwise_subject_secret,
        user_id,
        &protocol_logout_client(client),
    )
    .map_err(Into::into)
}

fn protocol_logout_client(client: &BackchannelLogoutClient) -> nazo_auth::LogoutClient {
    nazo_auth::LogoutClient {
        redirect_uris: json_value_strings(&client.redirect_uris),
        subject_type: client.subject_type.clone(),
        sector_identifier_host: client.sector_identifier_host.clone(),
    }
}

fn json_value_strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
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
    handles: &OidcLogoutHandles,
    limit: i64,
) -> anyhow::Result<Vec<BackchannelLogoutDelivery>> {
    handles
        .claim_due_backchannel_logout(limit, BACKCHANNEL_LOGOUT_LOCK_TIMEOUT_SECONDS as i32)
        .await
        .map_err(|error| anyhow::anyhow!("failed to claim backchannel logout: {error}"))
}

async fn mark_backchannel_logout_delivery_success(
    handles: &OidcLogoutHandles,
    delivery: &BackchannelLogoutDelivery,
) -> anyhow::Result<()> {
    handles
        .complete_backchannel_logout(delivery)
        .await
        .map_err(|error| anyhow::anyhow!("failed to complete backchannel logout: {error}"))
}

async fn mark_backchannel_logout_delivery_failure(
    handles: &OidcLogoutHandles,
    delivery: &BackchannelLogoutDelivery,
    error: &str,
) -> anyhow::Result<()> {
    let now = Utc::now();
    let last_error = truncate_backchannel_logout_error(error);
    let next_attempt_at =
        backchannel_logout_next_retry_at(delivery.attempts - 1, now, delivery.expires_at);
    handles
        .fail_backchannel_logout(delivery, next_attempt_at, &last_error)
        .await
        .map_err(|error| anyhow::anyhow!("failed to update backchannel logout: {error}"))
}

fn truncate_backchannel_logout_error(error: &str) -> String {
    error
        .chars()
        .take(BACKCHANNEL_LOGOUT_ERROR_MAX_CHARS)
        .collect()
}

async fn process_backchannel_logout_delivery_batch_with_handles(
    handles: &OidcLogoutHandles,
) -> anyhow::Result<usize> {
    let deliveries =
        claim_due_backchannel_logout_deliveries(handles, BACKCHANNEL_LOGOUT_DELIVERY_BATCH_SIZE)
            .await?;
    let processed = deliveries.len();
    for delivery in deliveries {
        match post_backchannel_logout(&delivery.logout_uri, &delivery.logout_token).await {
            Ok(()) => mark_backchannel_logout_delivery_success(handles, &delivery).await?,
            Err(error) => {
                let error_message = error.to_string();
                tracing::warn!(
                    error = %error_message,
                    backchannel_logout_uri = %delivery.logout_uri,
                    "backchannel logout delivery failed"
                );
                mark_backchannel_logout_delivery_failure(handles, &delivery, &error_message)
                    .await?;
            }
        }
    }
    Ok(processed)
}

#[cfg(not(test))]
pub(crate) fn spawn_backchannel_logout_delivery_worker(handles: Data<OidcLogoutHandles>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) =
                process_backchannel_logout_delivery_batch_with_handles(&handles).await
            {
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
