use crate::config::ConfigSource;

// These broad admission-control buckets are keyed by source IP. A high default
// avoids treating an enterprise NAT or shared proxy as one abusive client.
// Credential guessing remains independently constrained by
// the much stricter IP-and-email failed-login policy below.
const DEFAULT_SHARED_IP_MAX_REQUESTS: u64 = 100_000;

pub(crate) use nazoauth::config::RateLimitSettings;

pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<RateLimitSettings> {
    let settings = RateLimitSettings {
        window_seconds: config.parse("RATE_LIMIT_WINDOW_SECONDS", 60)?,
        auth_max_requests: config.parse(
            "AUTH_RATE_LIMIT_MAX_REQUESTS",
            DEFAULT_SHARED_IP_MAX_REQUESTS,
        )?,
        token_max_requests: config.parse(
            "TOKEN_RATE_LIMIT_MAX_REQUESTS",
            DEFAULT_SHARED_IP_MAX_REQUESTS,
        )?,
        token_management_max_requests: config.parse(
            "TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS",
            DEFAULT_SHARED_IP_MAX_REQUESTS,
        )?,
        scim_denial_max_requests: config.parse("SCIM_DENIAL_RATE_LIMIT_MAX_REQUESTS", 60)?,
        login_failure_window_seconds: config.parse("LOGIN_FAILURE_WINDOW_SECONDS", 900)?,
        login_failure_ip_email_max_attempts: config
            .parse("LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS", 5)?,
        mfa_failure_window_seconds: config.parse("MFA_FAILURE_WINDOW_SECONDS", 900)?,
        mfa_failure_max_attempts: config.parse("MFA_FAILURE_MAX_ATTEMPTS", 5)?,
    };
    Ok(settings)
}
