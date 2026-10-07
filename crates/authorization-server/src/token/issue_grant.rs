use super::*;
use chrono::{Duration, Utc};
use nazo_auth::{CommitTokenIssuanceResult, GrantType, TokenIssuanceMode};
use uuid::Uuid;

#[allow(clippy::needless_return)]
pub async fn issue_token_response(
    context: &TokenIssuanceContext<'_>,
    token_service: &ServerTokenService,
    client: &ClientRow,
    mode: TokenIssuanceMode,
    mut issue: TokenIssue,
) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
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
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权详情状态无效.",
                false,
            ));
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
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "openid 授权缺少用户主体.",
            false,
        ));
    }
    if issue_includes_openid && issue.refresh_authority.is_some() && issue.auth_time.is_none() {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "refresh_id_token_authentication_context_missing",
            auth_code_ttl_seconds,
        )
        .await;
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refreshed ID token requires the original authentication context.",
            false,
        ));
    }
    if issue.native_sso.is_some() && !context.permits(nazo_runtime_modules::ModuleId::NativeSso) {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "native_sso_disabled",
            auth_code_ttl_seconds,
        )
        .await;
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO is not enabled.",
            false,
        ));
    }
    if issue.native_sso.is_some() && !issue_includes_openid {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "native_sso_without_openid",
            auth_code_ttl_seconds,
        )
        .await;
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO requires openid.",
            false,
        ));
    }
    if !refresh_issue_matches_source(&issue, client, context.config.issuer()) {
        return Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token source authority is missing or inconsistent.",
            false,
        ));
    }
    let refresh_authorization_scopes = issue
        .refresh_authority
        .as_ref()
        .map(|source| source.contract.scopes.as_slice())
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
    let refresh_authentication_context = if will_issue_refresh
        && matches!(issue.refresh_token_policy, RefreshTokenPolicy::IssueNew)
    {
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
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token requires a complete authentication context.",
                false,
            ));
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
        return Err(OAuthEndpointError::token(
            StatusCode::UNAUTHORIZED,
            "invalid_client_attestation",
            "Client attestation refresh-token binding is missing.",
            false,
        ));
    }
    // Only OIDC claims construction consumes the subject profile; non-OIDC
    // user access tokens rely on the commit's principal lock recheck.
    let subject_claims_snapshot = if issue_includes_openid && let Some(user_id) = issue.user_id {
        let prepared = match issue.prepared_subject.take() {
            Some(prepared) => prepared,
            None => match token_service
                .active_subject_claims(client.tenant_id, user_id, &issue.subject)
                .await
            {
                Ok(Some(claims)) => claims,
                Ok(None) => {
                    mark_failed_authorization_code_if_needed(
                        token_service,
                        issue.authorization_code_hash.as_deref(),
                        "token_subject_invalid",
                        auth_code_ttl_seconds,
                    )
                    .await;
                    return Err(OAuthEndpointError::token(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "授权用户不存在或已停用.",
                        false,
                    ));
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
                    return Err(OAuthEndpointError::token(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "授权用户状态加载失败.",
                        false,
                    ));
                }
            },
        };
        if prepared.tenant_id != client.tenant_id
            || prepared.claims.subject.as_uuid() != user_id
            || prepared.token_subject != issue.subject
        {
            tracing::error!("prepared subject snapshot does not match the issuance context");
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "token_subject_snapshot_mismatch",
                auth_code_ttl_seconds,
            )
            .await;
            return Err(OAuthEndpointError::token(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "令牌签发失败.",
                false,
            ));
        }
        Some(prepared)
    } else {
        None
    };
    let principal_state = if issue.user_id.is_none() {
        // Authentication already read this version before signing. The commit
        // still locks the client and rejects a deactivate/reactivate race.
        nazo_auth::TokenPrincipalState {
            client_epoch: context.client_epoch,
            user_epoch: None,
            subject_bound: false,
        }
    } else if let Some(snapshot) = subject_claims_snapshot.as_ref() {
        // OIDC claims, their epoch and the exact subject's binding were read
        // together. Never endorse old claims with a newer principal epoch.
        // Commit still rechecks both principal versions under lock.
        nazo_auth::TokenPrincipalState {
            client_epoch: context.client_epoch,
            user_epoch: Some(snapshot.user_epoch),
            subject_bound: snapshot.subject_bound,
        }
    } else {
        match token_service
            .token_principal_state(
                client.tenant_id,
                context.client_epoch,
                issue.user_id,
                &issue.subject,
            )
            .await
        {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(%error, "failed to read token principal state");
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "token_principal_state_unavailable",
                    auth_code_ttl_seconds,
                )
                .await;
                return Err(OAuthEndpointError::token(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "令牌主体状态不可用.",
                    false,
                ));
            }
        }
    };
    let issuance_id = Uuid::now_v7();
    // Commit-owned issuance: when the final commit transaction carries both
    // the principal-version check and required `token_issued` append, the
    // commit itself is the fail-closed writer check, so the per-request
    // static capability probe is redundant. Normal refresh rotation and
    // preserving an existing refresh token join the no-refresh shape: any
    // family lock and spent-proof bookkeeping are owned by
    // that same commit transaction. Any path
    // with a preceding durable side effect (authorization-code consumption,
    // Native SSO device-secret persistence) keeps the full storage
    // preflight, and `RotateLostResponse` stays on it as well — the retry
    // proves its direct-predecessor edge inside the commit but the
    // lost-response recovery path is deliberately kept conservative.
    let commit_owned = matches!(mode, TokenIssuanceMode::Fresh)
        && issue.authorization_code_hash.is_none()
        && issue.native_sso.is_none()
        && (!will_issue_refresh
            || matches!(
                issue.refresh_token_policy,
                RefreshTokenPolicy::PreserveExisting | RefreshTokenPolicy::Rotate { .. }
            ));
    let audit_ready = if commit_owned {
        context.security_audit.ensure_transactional_ready().await
    } else {
        context.security_audit.ensure_storage().await
    };
    if let Err(error) = audit_ready {
        tracing::error!(%error, "token issuance audit preflight failed");
        return Err(OAuthEndpointError::token(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "令牌签发审计存储不可用.",
            false,
        ));
    }
    let now = Utc::now();
    // Select the owned lineage before signing. Only a checked refresh source
    // can inherit it; unrelated fresh exchanges get a new issuance root.
    let refresh_family = if will_issue_refresh {
        match issue.refresh_token_policy {
            RefreshTokenPolicy::IssueNew => Some((Uuid::now_v7(), None, None)),
            RefreshTokenPolicy::Rotate {
                family_id,
                rotated_from_id,
            } => Some((family_id, Some(rotated_from_id), None)),
            RefreshTokenPolicy::RotateLostResponse {
                family_id,
                original_id,
                original_blake3,
                successor_id,
                retry_started_at,
            } => Some((
                family_id,
                Some(successor_id),
                Some((original_id, original_blake3, retry_started_at)),
            )),
            RefreshTokenPolicy::NoRefresh | RefreshTokenPolicy::PreserveExisting => None,
        }
    } else {
        None
    };
    let authorization_id = issue
        .refresh_authority
        .as_ref()
        .map(|source| source.family_id)
        .or_else(|| refresh_family.as_ref().map(|(family, _, _)| *family))
        .unwrap_or(issuance_id);
    let next_dpop_nonce = if issue.dpop_jkt.is_some() {
        match issue_authorization_server_dpop_nonce(context.authorization).await {
            Ok(nonce) => Some(nonce),
            Err(error) => {
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "dpop_next_nonce_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return Err(OAuthEndpointError::Dpop {
                    error,
                    context: DpopErrorContext::TokenEndpoint,
                });
            }
        }
    } else {
        None
    };
    let issued_access_token = match token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            authorization_id: Some(authorization_id),
            client_epoch: Some(principal_state.client_epoch),
            user_epoch: principal_state.user_epoch,
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
            return Err(OAuthEndpointError::token(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "令牌签发失败.",
                false,
            ));
        }
    };
    let token_type = if issue.dpop_jkt.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let scope = issue.scopes.join(" ");
    let mut body = json!({
        "token_type": token_type,
        "expires_in": context.config.access_token_ttl_seconds,
        "scope": scope
    });
    body["access_token"] = serde_json::Value::String(issued_access_token.token);
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
            .refresh_authority
            .as_ref()
            .map(|source| source.contract.scopes.as_slice())
            .unwrap_or(&issue.scopes);
        let loaded_claims = subject_claims_snapshot
            .as_ref()
            .expect("openid token issues have a validated subject snapshot");
        let mut user_claims = Some(oidc_id_token_user_claims(
            &loaded_claims.claims,
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
        if issue.refresh_authority.is_some()
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
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token 无法满足原始 ID Token 必需声明.",
                false,
            ));
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
                nonce: if issue.refresh_authority.is_some() {
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
                return Err(OAuthEndpointError::token(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "id_token 签发失败.",
                    false,
                ));
            }
        };
        let id_token = match client_jwe_key(
            client.jwks.as_ref(),
            client.id_token_encrypted_response_alg.as_deref(),
            client.id_token_encrypted_response_enc.as_deref(),
            "id_token",
        )
        .and_then(|key| match key {
            Some(key) => {
                encrypt_compact_jwe(&key, signed_id_token.as_bytes(), JwePayloadKind::NestedJwt)
            }
            None => Ok(signed_id_token),
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
                return Err(OAuthEndpointError::token(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "id_token 加密失败.",
                    false,
                ));
            }
        };
        body["id_token"] = serde_json::Value::String(id_token);
    }
    let mut refresh_token_to_commit = None;
    if will_issue_refresh && let Some((family, rotated_from, lost_response_retry)) = refresh_family
    {
        let refresh = PendingRefreshToken {
            raw: format!("{}.{}", random_urlsafe_token(), random_urlsafe_token()),
            member_id: Uuid::now_v7(),
            family,
            rotated_from,
            lost_response_retry,
            issued_at: now,
            expires_at: now + Duration::seconds(context.config.refresh_token_ttl_seconds),
        };
        let id_token_sid_for_refresh_persistence =
            persisted_id_token_sid(&issue, issued_id_token_sid.as_deref());
        let refresh_token = prepare_refresh_token(
            client,
            &issue,
            &refresh,
            id_token_sid_for_refresh_persistence.map(ToOwned::to_owned),
        );
        body["refresh_token"] = serde_json::Value::String(refresh.raw);
        refresh_token_family_id = Some(refresh.family);
        refresh_token_to_commit = Some(refresh_token);
    }
    let refresh_commit = if let Some(authority) = issue.refresh_authority.take() {
        Some(nazo_auth::RefreshTokenCommit::UseExisting {
            authority,
            rotation: refresh_token_to_commit,
        })
    } else {
        refresh_token_to_commit.map(|token| {
            let mut authentication_context = refresh_authentication_context
                .expect("new refresh family validated authentication context");
            authentication_context.nonce = None;
            authentication_context.id_token_sid = None;
            let contract = nazo_auth::RefreshContract {
                subject: issue.subject.clone(),
                scopes: issue.scopes.clone(),
                audiences: token.audiences.clone(),
                authorization_details: issue.authorization_details.clone(),
                authentication_context,
            };
            nazo_auth::RefreshTokenCommit::IssueNew { token, contract }
        })
    };
    if let Some(native_sso) = issue.native_sso.as_ref() {
        let Some(refresh_token_family_id) = refresh_token_family_id else {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "native_sso_refresh_token_missing",
                auth_code_ttl_seconds,
            )
            .await;
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO requires a refresh token session.",
                false,
            ));
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
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO device secret persistence failed.",
                false,
            ));
        }
        body["device_secret"] = json!(native_sso.device_secret);
    }
    // The stable fence and holder are independent; a conflict proves code
    // consumption, but only matching possession permits replay revocation.
    let code_redemption = match &mode {
        TokenIssuanceMode::AuthorizationCode {
            code_identity,
            holder,
            ..
        } => Some((code_identity.clone(), holder.clone())),
        _ => None,
    };
    let subject_hash = blake3_hex(&issue.subject);
    match token_service
        .commit_token_issuance(nazo_auth::CommitTokenIssuance {
            authorization_id: Some(authorization_id),
            native_sso_source: issue.native_sso_source,
            principal_state,
            subject: issue.subject,
            issuance_id,
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: issue.user_id,
            mode,
            access_token_jti: issued_access_token.jti,
            access_token_expires_at: issued_access_token.expires_at,
            refresh_token: refresh_commit,
            audit_fields: nazo_auth::TokenIssuedAuditFields {
                client_id: client.client_id.clone(),
                subject_hash,
                scope,
                audience: issue.audiences,
            },
        })
        .await
    {
        Ok(CommitTokenIssuanceResult::Committed) => {
            // Busy and Missing replays consult the durable receipt. Discard
            // the consumed payload; a cleanup failure cannot undo issuance.
            if let Some(code_hash) = issue.authorization_code_hash.as_deref()
                && let Err(error) = token_service.finalize_authorization_code(code_hash).await
            {
                tracing::warn!(%error, "failed to discard committed authorization code preparation");
            }
            return Ok(TokenEndpointSuccess::Issued {
                body,
                dpop_nonce: next_dpop_nonce,
            });
        }
        Ok(CommitTokenIssuanceResult::AlreadyUsed) => {
            // A different valid request representation still finds this code
            // fence. A different holder cannot use that fact as a revocation oracle.
            if let Some((grant_key, holder)) = code_redemption.as_ref() {
                match token_service
                    .single_use_redemption(client.tenant_id, client.id, grant_key)
                    .await
                {
                    Ok(Some(redemption))
                        if redemption.authorization_code_holder.as_ref().is_some_and(
                            |expected| {
                                crate::token::authorization_code::holder_matches_original(
                                    expected, holder,
                                )
                            },
                        ) =>
                    {
                        if let Err(error) = revoke_issued_authorization_code_tokens(
                            token_service,
                            client,
                            &redemption.access_token_jti,
                            redemption.access_token_expires_at.timestamp(),
                            redemption.refresh_token_family_id,
                        )
                        .await
                        {
                            tracing::warn!(%error, "failed to revoke tokens after single-use grant replay");
                            return Err(OAuthEndpointError::token(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "server_error",
                                "授权码重放撤销失败.",
                                false,
                            ));
                        }
                        return Err(OAuthEndpointError::token(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "授权码已被使用，相关令牌已撤销.",
                            false,
                        ));
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        tracing::warn!(
                            issuance_id = %issuance_id,
                            "single-use fence conflict without a committed redemption row"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to read single-use grant redemption");
                        return Err(OAuthEndpointError::token(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "授权码校验失败.",
                            false,
                        ));
                    }
                }
            }
            Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "令牌签发授权已使用.",
                false,
            ))
        }
        Ok(CommitTokenIssuanceResult::RefreshGrantUnavailable) => Err(OAuthEndpointError::token(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 授权已失效.",
            false,
        )),
        Ok(CommitTokenIssuanceResult::GrantExpired) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "grant_expired",
                auth_code_ttl_seconds,
            )
            .await;
            Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                match context.grant_type {
                    Some(GrantType::DeviceCode | GrantType::Ciba) => "expired_token",
                    _ => "invalid_grant",
                },
                "令牌签发授权已过期.",
                false,
            ))
        }
        Ok(CommitTokenIssuanceResult::ClientInactive) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "client_inactive",
                auth_code_ttl_seconds,
            )
            .await;
            Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "该客户端未启用当前授权类型.",
                false,
            ))
        }
        Ok(CommitTokenIssuanceResult::SubjectInactive) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "subject_inactive",
                auth_code_ttl_seconds,
            )
            .await;
            Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "授权用户不存在或已停用.",
                false,
            ))
        }
        Ok(CommitTokenIssuanceResult::RotationConflict) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "refresh_rotation_conflict",
                auth_code_ttl_seconds,
            )
            .await;
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token 无效或已撤销.",
                false,
            ));
        }
        Err(error) => {
            tracing::warn!(%error, issuance_id = %issuance_id, "failed to commit token issuance");
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "令牌签发状态写入失败.",
                false,
            ));
        }
    }
}
