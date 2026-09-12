//! 会话用户与权限解析。
use actix_web::http::StatusCode;
use nazo_oauth_server::sessions::{
    AdminSessionError, CurrentSession, SessionResolver, require_admin_session, require_recent_mfa,
};

use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::oauth_error;
use nazo_identity::PublicAccount;
use std::sync::Arc;

// 只处理从请求 Cookie 到当前用户/管理员身份的解析。

use nazo_http_actix::{
    authorization_error_response, clear_cookie, cookie_value, has_valid_csrf_token_for_cookies,
    with_cookie_headers,
};

/// Runtime-admin authentication dependencies, assembled once at the composition root.
///
/// This owns the application resolver and cookie configuration, without exposing
/// storage connections or complete server settings to HTTP handlers.
pub(crate) struct AdminSessionHandles {
    resolver: Arc<SessionResolver>,
    http: SessionHttpConfig,
}

/// Profile session endpoint dependencies assembled at the composition root.
///
/// The profile transport only receives the application resolver and cookie
/// configuration. It cannot reach raw storage connections, the keyset, or settings.
#[derive(Clone)]
pub(crate) struct SessionProfileHandles {
    resolver: Arc<SessionResolver>,
    http: SessionHttpConfig,
}

#[derive(Clone)]
pub(crate) struct SessionHttpConfig {
    session_cookie_name: Box<str>,
    csrf_cookie_name: Box<str>,
    cookie_secure: bool,
}

impl SessionHttpConfig {
    pub(crate) fn new(
        session_cookie_name: &str,
        csrf_cookie_name: &str,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            cookie_secure,
        }
    }

    pub(crate) fn session_cookie_name(&self) -> &str {
        &self.session_cookie_name
    }

    pub(crate) fn csrf_cookie_name(&self) -> &str {
        &self.csrf_cookie_name
    }

    pub(crate) fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }
}

impl AdminSessionHandles {
    pub(crate) fn new(resolver: Arc<SessionResolver>, http: SessionHttpConfig) -> Self {
        Self { resolver, http }
    }

    pub(crate) fn http_config(&self) -> &SessionHttpConfig {
        &self.http
    }

    pub(crate) async fn current_session(
        &self,
        req: &HttpRequest,
    ) -> anyhow::Result<Option<CurrentSession>> {
        let Some(session_id) = cookie_value(req, self.http.session_cookie_name()) else {
            return Ok(None);
        };
        self.resolver.current_session_by_id(&session_id).await
    }

    pub(crate) async fn current_session_or_login_required(
        &self,
        req: &HttpRequest,
    ) -> Result<CurrentSession, HttpResponse> {
        match self.current_session(req).await {
            Ok(Some(session)) => Ok(session),
            Ok(None) => Err(login_required_response_for_cookies(
                self.http.session_cookie_name(),
                self.http.csrf_cookie_name(),
                self.http.cookie_secure(),
            )),
            Err(error) => Err(session_lookup_error_response(error)),
        }
    }
}

impl SessionProfileHandles {
    pub(crate) fn new(resolver: Arc<SessionResolver>, http: SessionHttpConfig) -> Self {
        Self { resolver, http }
    }

    pub(crate) fn http_config(&self) -> &SessionHttpConfig {
        &self.http
    }

    pub(crate) fn has_valid_csrf_token(
        &self,
        req: &HttpRequest,
        fallback_token: Option<&str>,
    ) -> bool {
        has_valid_csrf_token_for_cookies(
            req,
            fallback_token,
            self.http.session_cookie_name(),
            self.http.csrf_cookie_name(),
        )
    }

    pub(crate) fn login_required_response(&self) -> HttpResponse {
        with_cookie_headers(
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "会话不存在或已过期,请重新登录.",
            ),
            &[
                clear_cookie(self.http.session_cookie_name(), self.http.cookie_secure()),
                clear_cookie(self.http.csrf_cookie_name(), self.http.cookie_secure()),
            ],
        )
    }

    pub(crate) async fn current_user_or_login_required(
        &self,
        req: &HttpRequest,
    ) -> Result<PublicAccount, HttpResponse> {
        match self.current_session(req).await {
            Ok(Some(session)) => Ok(session.user),
            Ok(None) => Err(self.login_required_response()),
            Err(error) => Err(session_lookup_error_response(error)),
        }
    }

    pub(crate) async fn current_session_or_login_required(
        &self,
        req: &HttpRequest,
    ) -> Result<CurrentSession, HttpResponse> {
        match self.current_session(req).await {
            Ok(Some(session)) => Ok(session),
            Ok(None) => Err(self.login_required_response()),
            Err(error) => Err(session_lookup_error_response(error)),
        }
    }

    pub(crate) async fn current_session(
        &self,
        req: &HttpRequest,
    ) -> anyhow::Result<Option<CurrentSession>> {
        let Some(session_id) = cookie_value(req, self.http.session_cookie_name()) else {
            return Ok(None);
        };
        self.resolver.current_session_by_id(&session_id).await
    }
}

fn login_required_response_for_cookies(
    session_cookie_name: &str,
    csrf_cookie_name: &str,
    cookie_secure: bool,
) -> HttpResponse {
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(session_cookie_name, cookie_secure),
            clear_cookie(csrf_cookie_name, cookie_secure),
        ],
    )
}

pub(crate) async fn require_admin_or_forbidden_with_handles(
    handles: &AdminSessionHandles,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    current_admin_session_or_forbidden(handles, req)
        .await
        .map(|session| session.user)
}

/// Authorizes an administrator for a high-impact state mutation.
///
/// A normal administrator session is sufficient for read-only admin views, but
/// writes additionally require a recent *interactive* MFA step-up.  A
/// `remembered_mfa` marker by itself is not accepted: it proves a previously
/// trusted device, not a factor entered for this privileged operation.  The
/// marker may remain alongside `otp`/`recovery_code` after a later explicit
/// step-up because AMR is cumulative for the browser session.
/// The existing `/mfa/step-up` endpoint performs that rotation; no separate
/// admin-only challenge or bypass token is introduced here.
pub(crate) async fn require_admin_with_recent_mfa_or_forbidden_with_handles(
    handles: &AdminSessionHandles,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    let session = current_admin_session_or_forbidden(handles, req).await?;
    require_recent_mfa(&session, Utc::now().timestamp()).map_err(admin_session_error_response)?;
    Ok(session.user)
}

async fn current_admin_session_or_forbidden(
    handles: &AdminSessionHandles,
    req: &HttpRequest,
) -> Result<CurrentSession, HttpResponse> {
    let session = handles
        .current_session(req)
        .await
        .map_err(session_lookup_error_response)?;
    require_admin_session(session).map_err(admin_session_error_response)
}

fn admin_session_error_response(error: AdminSessionError) -> HttpResponse {
    match error {
        AdminSessionError::AccessDenied => oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前账号无管理权限.",
        ),
        AdminSessionError::MfaStepUpRequired => authorization_error_response(
            StatusCode::PRECONDITION_REQUIRED,
            "mfa_step_up_required",
            "高影响管理员操作需要最近一次多因素认证.",
        ),
    }
}

fn session_lookup_error_response(error: anyhow::Error) -> HttpResponse {
    tracing::warn!(%error, "failed to resolve current session user");
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "会话查询失败.",
    )
}

#[cfg(test)]
#[path = "../../tests/support/http/sessions.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../../tests/unit/http/sessions.rs"]
mod tests;
