//! OIDC RP-Initiated Logout and Back-Channel Logout support.
//! The endpoint clears the OP browser session locally and best-effort notifies
//! registered relying parties that have a backchannel logout URI.

use crate::http::prelude::*;
use actix_web::web::Payload;

#[derive(Default)]
struct LogoutRequest {
    id_token_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Clone, Debug, Queryable)]
struct BackchannelLogoutClient {
    client_id: String,
    redirect_uris: Value,
    post_logout_redirect_uris: Value,
    backchannel_logout_uri: Option<String>,
    subject_type: String,
    sector_identifier_host: Option<String>,
}

#[derive(Clone, Debug, Queryable)]
struct FrontchannelLogoutClient {
    client_id: String,
    frontchannel_logout_uri: String,
    frontchannel_logout_session_required: bool,
}

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

    let frontchannel_urls =
        if state.settings.enable_frontchannel_logout && current_session.is_some() {
            match frontchannel_logout_clients_for_user(
                &state,
                current_session
                    .as_ref()
                    .expect("checked current_session is present")
                    .user
                    .id,
            )
            .await
            {
                Ok(clients) => clients
                    .iter()
                    .filter_map(|client| {
                        frontchannel_logout_url(
                            client,
                            &state.settings.issuer,
                            &current_session
                                .as_ref()
                                .expect("checked current_session is present")
                                .oidc_sid,
                        )
                        .map_err(|error| {
                            tracing::warn!(
                                %error,
                                client_id = %client.client_id,
                                "failed to compose front-channel logout URI"
                            );
                        })
                        .ok()
                    })
                    .collect::<Vec<_>>(),
                Err(error) => {
                    tracing::warn!(%error, "failed to query front-channel logout clients");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

    if let Some(session_id) = session_cookie {
        let _ = valkey_del(&state.valkey, format!("oauth:session:{session_id}")).await;
    }

    if let Some(session) = current_session.as_ref() {
        dispatch_backchannel_logout(&state, session, hint.as_ref(), client.as_ref()).await;
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
                        .map(|session| blake3_hex(&session.user.id.to_string()))
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
    let iframes = frontchannel_urls
        .iter()
        .map(|url| {
            format!(
                "<iframe title=\"OIDC Front-Channel Logout\" src=\"{}\"></iframe>",
                escape_html_attribute(url)
            )
        })
        .collect::<String>();
    let redirect_script = redirect.map_or_else(String::new, |location| {
        format!(
            "<script>setTimeout(function(){{window.location.replace('{}');}},300);</script>",
            escape_js_string(location)
        )
    });
    format!(
        concat!(
            "<!doctype html><html><head><meta charset=\"utf-8\">",
            "<meta http-equiv=\"cache-control\" content=\"no-store\">",
            "<style>iframe{{display:none;width:0;height:0;border:0}}</style>",
            "</head><body>{iframes}{redirect_script}</body></html>"
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
                session.user.id,
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
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for oidc logout client lookup");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "logout client lookup failed.",
        )
    })?;
    oauth_clients::table
        .filter(oauth_clients::client_id.eq(client_id))
        .filter(oauth_clients::is_active.eq(true))
        .select((
            oauth_clients::client_id,
            oauth_clients::redirect_uris,
            oauth_clients::post_logout_redirect_uris,
            oauth_clients::backchannel_logout_uri,
            oauth_clients::subject_type,
            oauth_clients::sector_identifier_host,
        ))
        .first::<BackchannelLogoutClient>(&mut conn)
        .await
        .optional()
        .map_err(|error| {
            tracing::warn!(%error, "failed to query oidc logout client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "logout client lookup failed.",
            )
        })
        .and_then(|client| {
            client.map_or_else(
                || {
                    Err(oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "logout client is not registered or active.",
                    ))
                },
                |client| Ok(Some(client)),
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

async fn dispatch_backchannel_logout(
    state: &AppState,
    session: &CurrentSession,
    hint: Option<&IdTokenHintClaims>,
    hinted_client: Option<&BackchannelLogoutClient>,
) {
    if let Some(hint) = hint
        && !id_token_hint_matches_current_session(
            &state.settings,
            hinted_client,
            session.user.id,
            &session.oidc_sid,
            hint,
        )
    {
        tracing::warn!("id_token_hint subject or sid did not match the current OP session");
        return;
    }
    let clients = match backchannel_logout_clients_for_user(state, session.user.id).await {
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
        Err(error) => {
            tracing::warn!(%error, "failed to query backchannel logout clients");
            return;
        }
    };
    for client in clients {
        let Some(uri) = client.backchannel_logout_uri.clone() else {
            continue;
        };
        let subject =
            match unique_logout_subject_for_client(&state.settings, session.user.id, &client) {
                Ok(subject) => subject,
                Err(_) => continue,
            };
        let token = match make_backchannel_logout_token(
            state,
            BackchannelLogoutTokenInput {
                client_id: &client.client_id,
                subject: subject.as_deref(),
                sid: Some(session.oidc_sid.as_str()),
                ttl: 120,
            },
        )
        .await
        {
            Ok(token) => token,
            Err(error) => {
                tracing::warn!(%error, client_id = %client.client_id, "failed to sign logout token");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(error) = post_backchannel_logout(&uri, &token).await {
                let error_message = error.to_string();
                tracing::warn!(error = %error_message, backchannel_logout_uri = %uri, "backchannel logout delivery failed");
            }
        });
    }
}

async fn backchannel_logout_clients_for_user(
    state: &AppState,
    user_id: Uuid,
) -> anyhow::Result<Vec<BackchannelLogoutClient>> {
    let mut conn = get_conn(&state.diesel_db).await?;
    Ok(user_client_grants::table
        .inner_join(oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)))
        .filter(user_client_grants::user_id.eq(user_id))
        .filter(oauth_clients::is_active.eq(true))
        .filter(oauth_clients::backchannel_logout_uri.is_not_null())
        .select((
            oauth_clients::client_id,
            oauth_clients::redirect_uris,
            oauth_clients::post_logout_redirect_uris,
            oauth_clients::backchannel_logout_uri,
            oauth_clients::subject_type,
            oauth_clients::sector_identifier_host,
        ))
        .load::<BackchannelLogoutClient>(&mut conn)
        .await?)
}

async fn frontchannel_logout_clients_for_user(
    state: &AppState,
    user_id: Uuid,
) -> anyhow::Result<Vec<FrontchannelLogoutClient>> {
    let mut conn = get_conn(&state.diesel_db).await?;
    Ok(user_client_grants::table
        .inner_join(oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)))
        .filter(user_client_grants::user_id.eq(user_id))
        .filter(oauth_clients::is_active.eq(true))
        .filter(oauth_clients::frontchannel_logout_uri.is_not_null())
        .select((
            oauth_clients::client_id,
            oauth_clients::frontchannel_logout_uri.assume_not_null(),
            oauth_clients::frontchannel_logout_session_required,
        ))
        .load::<FrontchannelLogoutClient>(&mut conn)
        .await?)
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

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/oidc_logout.rs"]
mod tests;
