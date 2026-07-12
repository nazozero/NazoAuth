//! 用户注册端点。
// 注册只接受已验证邮箱，密码进入数据库前必须完成 Argon2 哈希。
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct RegisterRequest {
    email: String,
    verification_code: String,
    password: String,
}

/// 使用邮箱验证码创建本地用户。
pub(crate) async fn register(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<RegisterRequest>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }

    register_after_rate_limit(state, payload).await
}

pub(crate) async fn register_after_rate_limit(
    state: Data<AppState>,
    payload: RegisterRequest,
) -> HttpResponse {
    let Ok(email) = normalize_email_address(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let code = verification_code_for_lookup(&payload);
    let key = format!("oauth:email_verify:code:{email}");
    let stored = match valkey_get(&state.valkey, &key).await {
        Ok(value) => value,
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "验证码校验失败.",
            );
        }
    };
    if !stored
        .as_deref()
        .is_some_and(|stored| verify_password(&code, stored))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "验证码错误或已过期.",
        );
    }

    match find_user_by_email(&state.diesel_db, &email).await {
        Ok(Some(_)) => {
            return oauth_error(StatusCode::CONFLICT, "invalid_request", "该邮箱已注册.");
        }
        Ok(None) => {}
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "数据库连接失败.",
            );
        }
    }

    let password_hash = match hash_password(&payload.password) {
        Ok(v) => v,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "密码哈希失败.",
            );
        }
    };
    let password_hash = match nazo_identity::PasswordHash::new(password_hash) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::error!(%error, "generated password hash is invalid");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "密码哈希失败.",
            );
        }
    };
    let username = format!("user_{}", Uuid::now_v7());
    let tenant = default_tenant_context();
    let row = nazo_postgres::UserRepository::new(state.diesel_db.clone())
        .create(nazo_identity::ports::NewUser {
            tenant: tenant
                .as_identity_context()
                .expect("default tenant identifiers are valid"),
            username,
            email: email.clone(),
            password_hash,
            email_verified: true,
        })
        .await;
    match row {
        Ok(user) => {
            if !tenant.includes_user(&user) {
                tracing::warn!("created user returned outside the default tenant context");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "用户创建失败.",
                );
            }
            let _ = valkey_del(&state.valkey, &key).await;
            register_success_response(user)
        }
        Err(nazo_identity::ports::RepositoryError::Conflict) => {
            let _ = valkey_del(&state.valkey, &key).await;
            oauth_error(StatusCode::CONFLICT, "invalid_request", "该邮箱已注册.")
        }
        Err(error) => {
            tracing::warn!(%error, "failed to create user");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户创建失败.",
            )
        }
    }
}

fn verification_code_for_lookup(payload: &RegisterRequest) -> String {
    payload.verification_code.trim().to_owned()
}

fn register_success_response(user: PublicAccount) -> HttpResponse {
    json_response_status(
        StatusCode::CREATED,
        json!({"id": user.id(), "email": user.account.email}),
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/register.rs"]
mod tests;
