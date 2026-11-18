use super::*;
use crate::{AccountIdentity, Principal, TenantContext, UserProfile, UserRole};

fn account() -> PublicAccount {
    let now = jiff::Timestamp::now();
    PublicAccount {
        principal: Principal {
            authorization_epoch: 0,
            user_id: UserId::new(Uuid::from_u128(100)).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "alice".to_owned(),
            email: "alice@example.com".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn uv_initialization_requires_fresh_independent_mfa_bound_to_the_account() {
    let account = account();
    let now = 1_800_000_000;
    let mut session = CurrentSession {
        user: account.clone(),
        pending_mfa: false,
        auth_time: now,
        auth_time_micros: None,
        amr: vec!["passkey".into(), "otp".into(), "mfa".into()],
        oidc_sid: "test".into(),
        logged_in_client_ids: Vec::new(),
    };
    for method in ["otp", "recovery_code"] {
        session.amr = vec!["passkey".into(), method.into(), "mfa".into()];
        assert!(authorizes_uv_initialization(&session, &account, now));
        assert!(authorizes_uv_initialization(&session, &account, now + 300));
        assert!(!authorizes_uv_initialization(&session, &account, now + 301));
        assert!(!authorizes_uv_initialization(&session, &account, now - 1));
    }
    for amr in [
        vec!["passkey", "passkey_uv", "mfa"],
        vec!["passkey", "remembered_mfa", "mfa"],
        vec!["pwd"],
        vec!["passkey", "otp"],
    ] {
        session.amr = amr.into_iter().map(str::to_owned).collect();
        assert!(!authorizes_uv_initialization(&session, &account, now));
    }
    session.amr = vec!["pwd".into(), "otp".into(), "mfa".into()];
    session.pending_mfa = true;
    assert!(!authorizes_uv_initialization(&session, &account, now));
    session.pending_mfa = false;
    session.user.principal.authorization_epoch += 1;
    assert!(!authorizes_uv_initialization(&session, &account, now));
    session.user = account.clone();
    session.user.principal.user_id = UserId::new(Uuid::from_u128(101)).unwrap();
    assert!(!authorizes_uv_initialization(&session, &account, now));
    session.user = account.clone();
    session.user.principal.tenant.tenant_id = TenantId::new(Uuid::from_u128(102)).unwrap();
    assert!(!authorizes_uv_initialization(&session, &account, now));
}
