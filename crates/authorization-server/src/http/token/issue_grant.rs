use super::*;
use chrono::{Duration, Utc};
use nazo_auth::{CommitTokenIssuanceResult, TokenIssuanceMode};

#[allow(clippy::needless_return)]
pub(crate) async fn issue_token_response(
    context: &TokenIssuanceContext<'_>,
    token_service: &ServerTokenService,
    client: &ClientRow,
    mode: TokenIssuanceMode,
    mut issue: TokenIssue,
) -> HttpResponse {
    let auth_code_ttl_seconds = context.config.auth_code_ttl_seconds.max(1);
    issue.authorization_details = match normalize_authorization_details(issue.authorization_details)
    {
        Ok(value) => value,
        Err(_) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "authorization_details_state_invalid",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权详情状态无效.",
                false,
            );
        }
    };
    let issue_includes_openid = issue.scopes.iter().any(|s| s == "openid");
    if issue_includes_openid && issue.user_id.is_none() {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "id_token_subject_missing",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "openid 授权缺少用户主体.",
            false,
        );
    }
    if issue_includes_openid && issue.refresh_token_scopes.is_some() && issue.auth_time.is_none() {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "refresh_id_token_authentication_context_missing",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refreshed ID token requires the original authentication context.",
            false,
        );
    }
    if issue.native_sso.is_some() && !context.permits(nazo_runtime_modules::ModuleId::NativeSso) {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "native_sso_disabled",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO is not enabled.",
            false,
        );
    }
    if issue.native_sso.is_some() && !issue_includes_openid {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "native_sso_without_openid",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO requires openid.",
            false,
        );
    }
    let refresh_authorization_scopes = issue
        .refresh_token_scopes
        .as_deref()
        .unwrap_or(&issue.scopes);
    let openid4vci_credential_authorization = context
        .config
        .openid4vci_audience(refresh_authorization_scopes, &issue.authorization_details)
        .is_some();
    let will_issue_refresh = issue.include_refresh
        && should_issue_refresh_token(
            client,
            refresh_authorization_scopes,
            openid4vci_credential_authorization,
        );
    let refresh_authentication_context = if will_issue_refresh {
        let Some(context) = refresh_authentication_context(
            &issue,
            context.config.issuer(),
            &client.client_id,
            None,
        ) else {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "refresh_authentication_context_missing",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token requires a complete authentication context.",
                false,
            );
        };
        Some(context)
    } else {
        None
    };
    if will_issue_refresh
        && client.token_endpoint_auth_method == "attest_jwt_client_auth"
        && issue.refresh_token_client_attestation_jkt.is_none()
    {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "client_attestation_binding_missing",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client_attestation",
            "Client attestation refresh-token binding is missing.",
            false,
        );
    }
    let subject_claims_snapshot = if let Some(user_id) = issue.user_id {
        match token_service
            .active_subject_claims(client.tenant_id, user_id)
            .await
        {
            Ok(Some(claims)) => Some(claims),
            Ok(None) => {
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "token_subject_invalid",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权用户不存在或已停用.",
                    false,
                );
            }
            Err(error) => {
                tracing::warn!(?error, "failed to validate token subject before issuance");
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "token_subject_load_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "授权用户状态加载失败.",
                    false,
                );
            }
        }
    } else {
        None
    };
    let issuance_id = Uuid::now_v7();
    let grant_key = mode.grant_key(issuance_id);
    let request_digest = issuance_request_digest(client, &issue, &grant_key);
    if let Err(error) = ensure_audit_storage().await {
        tracing::error!(%error, "token issuance audit preflight failed");
        return oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "令牌签发审计存储不可用.",
            false,
        );
    }
    if let TokenIssuanceMode::Idempotent { .. } = &mode {
        match token_service
            .token_issuance_by_grant(client.tenant_id, client.id, &grant_key)
            .await
        {
            Ok(Some(record)) if record.request_digest == request_digest => {
                if let Some(response) = response_from_token_issuance(&record) {
                    return response;
                }
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "幂等令牌签发结果不可恢复.",
                    false,
                );
            }
            Ok(Some(_)) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "幂等令牌签发请求不匹配.",
                    false,
                );
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to read idempotent token issuance");
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "令牌签发状态读取失败.",
                    false,
                );
            }
        }
    }
    let now = Utc::now();
    let next_dpop_nonce = if issue.dpop_jkt.is_some() {
        match issue_dpop_nonce_with_authorization_service(context.authorization).await {
            Ok(nonce) => Some(nonce),
            Err(error) => {
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "dpop_next_nonce_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return dpop_error_response(error, DpopErrorContext::TokenEndpoint);
            }
        }
    } else {
        None
    };
    let issued_access_token = match token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &context.config.issuer,
            tenant_id: client.tenant_id,
            subject: &issue.subject,
            user_id: issue.user_id,
            subject_type: if issue.user_id.is_some() {
                "user"
            } else {
                "client"
            },
            client_id: &client.client_id,
            audiences: &issue.audiences,
            scopes: &issue.scopes,
            authorization_details: &issue.authorization_details,
            userinfo_claims: &issue.userinfo_claims,
            userinfo_claim_requests: &issue.userinfo_claim_requests,
            ttl_seconds: context.config.access_token_ttl_seconds,
            dpop_jkt: issue.dpop_jkt.as_deref(),
            mtls_x5t_s256: issue.mtls_x5t_s256.as_deref(),
            actor: issue.actor.as_ref(),
        })
        .await
    {
        Ok(v) => v,
        Err(error) => {
            tracing::warn!(%error, "failed to sign access token");
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "access_token_signing_failed",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "令牌签发失败.",
                false,
            );
        }
    };
    if let Err(error) = persist_access_token_subject_mapping(
        token_service,
        context.config.access_token_ttl_seconds,
        &issued_access_token.jti,
        client.tenant_id,
        issue.user_id,
        &issue.subject,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist access token subject mapping");
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "access_token_subject_mapping_failed",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "令牌主体状态写入失败.",
            false,
        );
    }
    let token_type = if issue.dpop_jkt.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut body = json!({
        "access_token": issued_access_token.token,
        "token_type": token_type,
        "expires_in": context.config.access_token_ttl_seconds,
        "scope": issue.scopes.join(" ")
    });
    if !nazo_auth::authorization_details_empty(&issue.authorization_details) {
        body["authorization_details"] = issue.authorization_details.clone();
    }
    if let Some(issued_token_type) = issue.issued_token_type.as_deref() {
        body["issued_token_type"] = json!(issued_token_type);
    }
    let mut refresh_token_family_id = None;
    let mut issued_id_token_sid = None;
    if issue_includes_openid {
        let sector_identifier_host = client.sector_identifier_host.as_deref();
        let id_token_claim_scopes = issue
            .refresh_token_scopes
            .as_deref()
            .unwrap_or(&issue.scopes);
        let loaded_claims = subject_claims_snapshot
            .as_ref()
            .expect("openid token issues have a validated subject snapshot");
        let mut user_claims = Some(oidc_id_token_user_claims(
            loaded_claims,
            id_token_claim_scopes,
            &issue.subject,
            &issue.id_token_claims,
            &issue.id_token_claim_requests,
            sector_identifier_host,
        ));
        if let Some(native_sso) = issue.native_sso.as_ref() {
            let claims = user_claims.get_or_insert_with(|| json!({}));
            if let Some(claims) = claims.as_object_mut() {
                claims.insert("ds_hash".to_owned(), json!(native_sso.ds_hash));
            }
        }
        let frontchannel_logout_enabled =
            context.permits(nazo_runtime_modules::ModuleId::FrontchannelLogout);
        let id_token_sid = id_token_session_sid(client, &issue, frontchannel_logout_enabled)
            .map(ToOwned::to_owned);
        issued_id_token_sid = id_token_sid.clone();
        if issue.refresh_token_scopes.is_some()
            && !refreshed_id_token_essential_claims_satisfied(
                &issue,
                client,
                frontchannel_logout_enabled,
                user_claims.as_ref(),
            )
        {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "refresh_id_token_essential_claim_missing",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token 无法满足原始 ID Token 必需声明.",
                false,
            );
        }
        let signed_id_token = match token_service
            .sign_id_token(nazo_auth::IdTokenSignInput {
                issuer: &context.config.issuer,
                subject: &issue.subject,
                client_id: &client.client_id,
                // OIDC Core 12.2 says a refreshed ID Token SHOULD omit
                // nonce.  The original value remains in `issue.nonce` so
                // the successor refresh contract can retain it, but it is
                // never emitted for a refresh issuance.
                nonce: if issue.refresh_token_scopes.is_some() {
                    None
                } else {
                    issue.nonce.as_deref()
                },
                auth_time: issue.auth_time,
                amr: &issue.amr,
                sid: id_token_sid.as_deref(),
                acr: issue.acr.as_deref(),
                extra_claims: user_claims.as_ref(),
                ttl_seconds: context.config.id_token_ttl_seconds,
                signing_algorithm: signing_algorithm_name(id_token_signing_alg_for_client(client)),
            })
            .await
        {
            Ok(token) => token,
            Err(error) => {
                tracing::warn!(%error, "failed to sign id_token");
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "id_token_signing_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "id_token 签发失败.",
                    false,
                );
            }
        };
        let id_token = match client_jwe_key(
            client.jwks.as_ref(),
            client.id_token_encrypted_response_alg.as_deref(),
            client.id_token_encrypted_response_enc.as_deref(),
            "id_token",
        )
        .and_then(|key| {
            key.map_or_else(
                || Ok(signed_id_token.clone()),
                |key| {
                    encrypt_compact_jwe(&key, signed_id_token.as_bytes(), JwePayloadKind::NestedJwt)
                },
            )
        }) {
            Ok(token) => token,
            Err(error) => {
                tracing::warn!(%error, "failed to encrypt id_token");
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "id_token_encryption_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "id_token 加密失败.",
                    false,
                );
            }
        };
        body["id_token"] = json!(id_token);
    }
    let mut refresh_token_to_commit = None;
    if will_issue_refresh {
        let refresh_family = match issue.refresh_token_policy {
            RefreshTokenPolicy::IssueNew => Some((Uuid::now_v7(), None, None)),
            RefreshTokenPolicy::Rotate {
                family_id,
                rotated_from_id,
            } => Some((family_id, Some(rotated_from_id), None)),
            RefreshTokenPolicy::RotateLostResponse {
                family_id,
                original_id,
                successor_id,
                retry_started_at,
            } => Some((
                family_id,
                Some(successor_id),
                Some((original_id, retry_started_at)),
            )),
            RefreshTokenPolicy::PreserveExisting => None,
        };
        if let Some((family, rotated_from, lost_response_retry)) = refresh_family {
            let refresh = PendingRefreshToken {
                raw: format!("{}.{}", random_urlsafe_token(), random_urlsafe_token()),
                family,
                rotated_from,
                lost_response_retry,
                issued_at: now,
                expires_at: now + Duration::seconds(context.config.refresh_token_ttl_seconds),
            };
            let id_token_sid_for_refresh_persistence =
                persisted_id_token_sid(&issue, issued_id_token_sid.as_deref());
            let mut authentication_context = refresh_authentication_context
                .clone()
                .expect("refresh issuance validated authentication context");
            authentication_context.id_token_sid =
                id_token_sid_for_refresh_persistence.map(ToOwned::to_owned);
            let refresh_token =
                prepare_refresh_token(client, &issue, &refresh, authentication_context);
            body["refresh_token"] = json!(refresh.raw);
            refresh_token_family_id = Some(refresh.family);
            refresh_token_to_commit = Some(refresh_token);
        }
    }
    if let Some(native_sso) = issue.native_sso.as_ref() {
        let Some(refresh_token_family_id) = refresh_token_family_id else {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "native_sso_refresh_token_missing",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO requires a refresh token session.",
                false,
            );
        };
        if let Err(error) = persist_native_sso_device_secret(
            token_service,
            context.config.refresh_token_ttl_seconds,
            client,
            &issue,
            native_sso,
            refresh_token_family_id,
        )
        .await
        {
            tracing::warn!(%error, "failed to persist Native SSO device secret");
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "native_sso_device_secret_persist_failed",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO device secret persistence failed.",
                false,
            );
        }
        body["device_secret"] = json!(native_sso.device_secret);
    }
    let response_body = match serde_json::to_vec(&body) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize token issuance response");
            return oauth_token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "令牌签发响应序列化失败.",
                false,
            );
        }
    };
    let response_body_for_commit =
        matches!(mode, TokenIssuanceMode::Idempotent { .. }).then(|| response_body.clone());
    match token_service
        .commit_token_issuance(nazo_auth::CommitTokenIssuance {
            issuance_id,
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: issue.user_id,
            mode: mode.clone(),
            request_digest,
            access_token_jti: issued_access_token.jti.clone(),
            access_token_expires_at: issued_access_token.expires_at,
            response_body: response_body_for_commit,
            refresh_token: refresh_token_to_commit,
            audit_fields: nazo_auth::TokenIssuedAuditFields {
                client_id: client.client_id.clone(),
                subject_hash: blake3_hex(&issue.subject),
                scope: issue.scopes.join(" "),
                audience: issue.audiences.clone(),
            },
        })
        .await
    {
        Ok(CommitTokenIssuanceResult::Committed) => {
            if let Some(code_hash) = issue.authorization_code_hash.as_deref() {
                let consumed_state_ttl_seconds = consumed_authorization_code_ttl_seconds(
                    context.config.access_token_ttl_seconds,
                    context.config.refresh_token_ttl_seconds,
                    refresh_token_family_id,
                );
                if let Err(error) = token_service
                    .finalize_authorization_code(nazo_auth::IssuedAuthorizationCodeTokens {
                        client_id: client.id,
                        code_hash,
                        redemption_binding: &grant_key,
                        access_token_jti: &issued_access_token.jti,
                        access_token_expires_at: issued_access_token.expires_at,
                        refresh_token_family_id,
                        consumed_state_ttl_seconds,
                    })
                    .await
                {
                    tracing::warn!(%error, issuance_id = %issuance_id, "failed to finalize authorization code after token commit");
                    return oauth_token_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "授权码兑换状态写入失败.",
                        false,
                    );
                }
            }
            let mut response = json_response_no_store(body);
            if let Some(nonce) = next_dpop_nonce
                && let Ok(value) = HeaderValue::from_str(&nonce)
            {
                response
                    .headers_mut()
                    .insert(header::HeaderName::from_static("dpop-nonce"), value);
            }
            return response;
        }
        Ok(CommitTokenIssuanceResult::Existing(record)) => {
            if let Some(response) = response_from_token_issuance(&record) {
                return response;
            }
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "幂等令牌签发结果不可恢复.",
                false,
            );
        }
        Ok(CommitTokenIssuanceResult::Conflict) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "幂等令牌签发请求不匹配.",
            false,
        ),
        Ok(CommitTokenIssuanceResult::AlreadyUsed) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "令牌签发授权已使用.",
            false,
        ),
        Ok(CommitTokenIssuanceResult::RotationConflict) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "refresh_rotation_conflict",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token 无效或已撤销.",
                false,
            );
        }
        Err(error) => {
            tracing::warn!(%error, issuance_id = %issuance_id, "failed to commit token issuance");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "令牌签发状态写入失败.",
                false,
            );
        }
    }
}
