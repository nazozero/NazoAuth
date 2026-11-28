use jiff::Timestamp;
use kevy_store::SetCondition;
use nazo_auth::{
    AuthorizationCodeBeginResult, AuthorizationCodeState, AuthorizationCodeTransitionResult,
    AuthorizationFuture, AuthorizationPortError, AuthorizationRateDimension,
    AuthorizationStateSnapshot, AuthorizationStateStorePort, CodePayload, ConsentPayload,
    PushedAuthorizationRequest, TokenFuture, TokenStateStorePort,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Error, TenantState, decode, encode,
    storage::{deadline, now_ms, set_until},
    ttl,
};

#[derive(Deserialize)]
struct StoredCode {
    expires_at_ms: u64,
    state: AuthorizationCodeState,
}

#[derive(Serialize)]
struct CodeRef<'a> {
    expires_at_ms: u64,
    state: &'a AuthorizationCodeState,
}

#[derive(Serialize)]
struct ConsumingCode<'a> {
    expires_at_ms: u64,
    state: ConsumingState<'a>,
}

#[derive(Serialize)]
struct ConsumingState<'a> {
    status: &'static str,
    payload: &'a CodePayload,
    consuming_at: Timestamp,
}

impl TenantState {
    fn store_preparation<T: Serialize + ?Sized>(
        &self,
        key: &[u8],
        value: &T,
        seconds: u64,
    ) -> Result<(), AuthorizationPortError> {
        let raw = encode(value)?;
        let duration = ttl(seconds)?;
        if self
            .volatile
            .with(|store| store.set(key, raw, Some(duration), SetCondition::IfAbsent))
        {
            Ok(())
        } else {
            Err(AuthorizationPortError::Conflict)
        }
    }

    fn preparation<T: DeserializeOwned>(
        &self,
        key: &[u8],
    ) -> Result<Option<AuthorizationStateSnapshot<T>>, Error> {
        self.volatile
            .get_with(key, |raw| {
                raw.map(|raw| {
                    let payload = decode(raw)?;
                    let version = std::str::from_utf8(raw)
                        .map_err(|_| Error::CorruptData)?
                        .to_owned();
                    Ok(AuthorizationStateSnapshot { payload, version })
                })
                .transpose()
            })
            .map_err(|_| Error::Unavailable)?
    }

    fn store_authorization_code_record(
        &self,
        key: &[u8],
        state: &AuthorizationCodeState,
        seconds: u64,
    ) -> Result<(), Error> {
        let expires_at_ms = deadline(seconds)?;
        let raw = encode(&CodeRef {
            expires_at_ms,
            state,
        })?;
        self.volatile
            .with(|store| set_until(store, key, raw, expires_at_ms));
        Ok(())
    }
}

impl AuthorizationStateStorePort for TenantState {
    fn load_par<'a>(
        &'a self,
        request_uri: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>>
    {
        Box::pin(async move {
            self.preparation(&self.key("par", &[request_uri.as_bytes()]))
                .map_err(Into::into)
        })
    }

    fn compare_and_delete_par<'a>(
        &'a self,
        request_uri: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.compare_delete(
                &self.key("par", &[request_uri.as_bytes()]),
                expected.as_bytes(),
            )
            .map_err(Into::into)
        })
    }

    fn store_par<'a>(
        &'a self,
        request_uri: &'a str,
        payload: &'a PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.store_preparation(
                &self.key("par", &[request_uri.as_bytes()]),
                payload,
                ttl_seconds,
            )
        })
    }

    fn load_consent<'a>(
        &'a self,
        request_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<AuthorizationStateSnapshot<ConsentPayload>>> {
        Box::pin(async move {
            self.preparation(&self.key("consent", &[request_id.as_bytes()]))
                .map_err(Into::into)
        })
    }

    fn compare_and_delete_consent<'a>(
        &'a self,
        request_id: &'a str,
        expected: &'a str,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.compare_delete(
                &self.key("consent", &[request_id.as_bytes()]),
                expected.as_bytes(),
            )
            .map_err(Into::into)
        })
    }

    fn store_consent<'a>(
        &'a self,
        request_id: &'a str,
        payload: &'a ConsentPayload,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.store_preparation(
                &self.key("consent", &[request_id.as_bytes()]),
                payload,
                ttl_seconds,
            )
        })
    }

    fn store_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        state: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.store_authorization_code_record(
                &self.key("code", &[code_hash.as_bytes()]),
                state,
                ttl_seconds,
            )
            .map_err(Into::into)
        })
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.delete(&self.key("code", &[code_hash.as_bytes()]));
            Ok(())
        })
    }

    fn take_reauth_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, Option<i64>> {
        Box::pin(async move {
            self.take_json(&self.key("reauth", &[nonce.as_bytes()]))
                .map_err(Into::into)
        })
    }

    fn store_reauth_nonce<'a>(
        &'a self,
        nonce: &'a str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move {
            self.put_json(
                &self.key("reauth", &[nonce.as_bytes()]),
                &started_at,
                ttl_seconds,
            )
            .map_err(Into::into)
        })
    }

    fn consume_jar<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay_until(
                "jar",
                &[client_id.as_bytes(), jti.as_bytes()],
                expires_at,
                None,
            )
            .await
            .map_err(Into::into)
        })
    }

    fn consume_client_attestation_proof<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        window: nazo_auth::ClientAttestationProofWindow,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay_until(
                "client-attestation",
                &[client_id.as_bytes(), jti.as_bytes()],
                window.expires_at(),
                Some(window.not_before()),
            )
            .await
            .map_err(Into::into)
        })
    }

    fn consume_private_key_jwt<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay(
                "private-key-jwt",
                &[client_id.as_bytes(), jti.as_bytes()],
                ttl_seconds,
            )
            .await
            .map_err(Into::into)
        })
    }

    fn consume_jwt_bearer<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay(
                "jwt-bearer",
                &[client_id.as_bytes(), jti.as_bytes()],
                ttl_seconds,
            )
            .await
            .map_err(Into::into)
        })
    }

    fn consume_ciba_request_object<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires_at: i64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay_until(
                "ciba-request",
                &[client_id.as_bytes(), jti.as_bytes()],
                expires_at,
                None,
            )
            .await
            .map_err(Into::into)
        })
    }

    fn consume_dpop<'a>(
        &'a self,
        thumbprint: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move {
            self.consume_replay(
                "dpop",
                &[thumbprint.as_bytes(), jti.as_bytes()],
                ttl_seconds,
            )
            .await
            .map_err(Into::into)
        })
    }

    fn issue_dpop_nonce<'a>(
        &'a self,
        nonce: &'a str,
        ttl_seconds: u64,
    ) -> AuthorizationFuture<'a, ()> {
        Box::pin(async move { self.issue_nonce(nonce, ttl_seconds).map_err(Into::into) })
    }

    fn validate_dpop_nonce<'a>(&'a self, nonce: &'a str) -> AuthorizationFuture<'a, bool> {
        Box::pin(async move { self.nonce_valid(nonce).map_err(Into::into) })
    }

    fn increment_rate<'a>(
        &'a self,
        dimension: AuthorizationRateDimension,
        subject: &'a str,
        window_seconds: u64,
    ) -> AuthorizationFuture<'a, u64> {
        Box::pin(async move {
            let namespace = match dimension {
                AuthorizationRateDimension::Token => "rate-token",
                AuthorizationRateDimension::TokenManagement => "rate-token-management",
            };
            TenantState::increment_rate(self, namespace, subject, window_seconds)
                .map_err(Into::into)
        })
    }
}

impl TokenStateStorePort for TenantState {
    fn load_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
    ) -> TokenFuture<'a, Option<AuthorizationCodeState>> {
        Box::pin(async move {
            self.read_json::<StoredCode>(&self.key("code", &[code_hash.as_bytes()]))
                .map(|stored| {
                    stored
                        .filter(|stored| stored.expires_at_ms > now_ms())
                        .map(|stored| stored.state)
                })
                .map_err(Into::into)
        })
    }

    fn begin_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        consuming_at: Timestamp,
    ) -> TokenFuture<'a, AuthorizationCodeBeginResult> {
        Box::pin(async move {
            let key = self.key("code", &[code_hash.as_bytes()]);
            self.volatile
                .with(|store| -> Result<_, Error> {
                    let Some(raw) = store.get(&key)? else {
                        return Ok(AuthorizationCodeBeginResult::Missing);
                    };
                    let Ok(stored) = decode::<StoredCode>(&raw) else {
                        return Ok(AuthorizationCodeBeginResult::Malformed);
                    };
                    if stored.expires_at_ms <= now_ms() {
                        store.del(&[&key]);
                        return Ok(AuthorizationCodeBeginResult::Missing);
                    }
                    match stored.state {
                        AuthorizationCodeState::Pending { payload } => {
                            let replacement = encode(&ConsumingCode {
                                expires_at_ms: stored.expires_at_ms,
                                state: ConsumingState {
                                    status: "consuming",
                                    payload: &payload,
                                    consuming_at,
                                },
                            })?;
                            set_until(store, &key, replacement, stored.expires_at_ms);
                            Ok(AuthorizationCodeBeginResult::Consuming(payload))
                        }
                        AuthorizationCodeState::Consuming { .. } => {
                            Ok(AuthorizationCodeBeginResult::Busy)
                        }
                        AuthorizationCodeState::Consumed => {
                            Ok(AuthorizationCodeBeginResult::Consumed(
                                AuthorizationCodeState::Consumed,
                            ))
                        }
                        AuthorizationCodeState::Failed { .. } => {
                            Ok(AuthorizationCodeBeginResult::Failed)
                        }
                    }
                })
                .map_err(Into::into)
        })
    }

    fn mark_authorization_code<'a>(
        &'a self,
        code_hash: &'a str,
        replacement: &'a AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, AuthorizationCodeTransitionResult> {
        Box::pin(async move {
            let key = self.key("code", &[code_hash.as_bytes()]);
            let expires_at_ms = deadline(ttl_seconds)?;
            let replacement = encode(&CodeRef {
                expires_at_ms,
                state: replacement,
            })?;
            self.volatile
                .with(|store| -> Result<_, Error> {
                    let Some(raw) = store.get(&key)? else {
                        return Ok(AuthorizationCodeTransitionResult::Missing);
                    };
                    let Ok(stored) = decode::<StoredCode>(&raw) else {
                        return Ok(AuthorizationCodeTransitionResult::Malformed);
                    };
                    if stored.expires_at_ms <= now_ms() {
                        store.del(&[&key]);
                        return Ok(AuthorizationCodeTransitionResult::Missing);
                    }
                    match stored.state {
                        AuthorizationCodeState::Consuming { .. } => {
                            set_until(store, &key, replacement, expires_at_ms);
                            Ok(AuthorizationCodeTransitionResult::Applied)
                        }
                        AuthorizationCodeState::Pending { .. } => {
                            Ok(AuthorizationCodeTransitionResult::Pending)
                        }
                        AuthorizationCodeState::Consumed => {
                            Ok(AuthorizationCodeTransitionResult::Consumed)
                        }
                        AuthorizationCodeState::Failed { .. } => {
                            Ok(AuthorizationCodeTransitionResult::Failed)
                        }
                    }
                })
                .map_err(Into::into)
        })
    }

    fn delete_authorization_code<'a>(&'a self, code_hash: &'a str) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.delete(&self.key("code", &[code_hash.as_bytes()]));
            Ok(())
        })
    }

    fn increment_token_management_rate<'a>(
        &'a self,
        subject: &'a str,
        window_seconds: u64,
    ) -> TokenFuture<'a, u64> {
        Box::pin(async move {
            self.increment_rate("rate-token-management", subject, window_seconds)
                .map_err(Into::into)
        })
    }

    fn store_native_sso<'a>(
        &'a self,
        secret: &'a str,
        value: &'a serde_json::Value,
        ttl_seconds: u64,
    ) -> TokenFuture<'a, ()> {
        Box::pin(async move {
            self.put_json(
                &self.key("native-sso", &[secret.as_bytes()]),
                value,
                ttl_seconds,
            )
            .map_err(Into::into)
        })
    }

    fn load_native_sso<'a>(
        &'a self,
        secret: &'a str,
    ) -> TokenFuture<'a, Option<serde_json::Value>> {
        Box::pin(async move {
            self.read_json(&self.key("native-sso", &[secret.as_bytes()]))
                .map_err(Into::into)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/authorization.rs"]
mod tests;
