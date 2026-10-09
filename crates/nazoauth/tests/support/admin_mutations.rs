use super::{DatabaseUserFixture, TestInfrastructure, valkey::valkey_set_ex};
use crate::{
    config::ConfigSource,
    http::sessions::{AdminSessionHandles, SessionHttpConfig},
    schema::users,
    settings::Settings,
};
use actix_web::{HttpRequest, cookie::Cookie, web::Data};
use chrono::Utc;
use diesel::sql_types::{Int4, Text, Uuid as SqlUuid};
use diesel::{prelude::*, sql_query};
use diesel_async::RunQueryDsl;
use fred::{
    interfaces::ClientLike,
    prelude::{
        Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
    },
};
use nazo_http_actix::ClientIpConfig;
use nazo_identity::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, ports::AdminUserRepositoryPort,
};
use nazo_oauth_server::sessions::SessionPayload;
use nazo_postgres::{UserRepository, create_pool, get_conn};
use std::{sync::Arc, time::Duration as StdDuration};
use uuid::Uuid;

pub(crate) fn admin_user_dependencies(
    state: &Data<TestInfrastructure>,
) -> (
    Data<AdminSessionHandles>,
    Data<dyn AdminUserRepositoryPort>,
    Data<ClientIpConfig>,
) {
    let session = &state.settings.session;
    let endpoint = &state.settings.endpoint;
    (
        Data::new(AdminSessionHandles::new(
            std::sync::Arc::new(nazo_oauth_server::sessions::SessionResolver::new(
                Arc::new(nazo_valkey::SessionStore::new(&state.valkey_connection())),
                Arc::new(UserRepository::new(state.diesel_db.clone())),
                state.settings.tenant.context.tenant_id,
            )),
            SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
        )),
        Data::from(Arc::new(UserRepository::new(state.diesel_db.clone()))
            as Arc<dyn AdminUserRepositoryPort>),
        Data::new(ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        )),
    )
}

pub(crate) struct LiveAdminUsersFixture {
    pub(crate) state: Data<TestInfrastructure>,
}

impl LiveAdminUsersFixture {
    pub(crate) async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://issuer.example"),
            ("TRANSPORT_MODE", "direct-tls"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_admin_users_session"),
            ("CSRF_COOKIE_NAME", "nazo_admin_users_csrf"),
        ]);
        let settings = Settings::from_config(&config).expect("test settings should load");
        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_millis(1000);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_millis(1000);
            connection.internal_command_timeout = StdDuration::from_millis(1000);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey should connect");
        let diesel_db = create_pool(database_url, 4).expect("database pool should build");
        crate::test_support::initialize_audit_dependencies(&diesel_db);

        Some(Self {
            state: Data::new(TestInfrastructure {
                diesel_db,
                valkey,
                settings: Arc::new(settings),
                keyset: crate::test_support::test_key_manager(),
            }),
        })
    }

    pub(crate) async fn create_user(
        &self,
        suffix: &str,
        role: &str,
        admin_level: i32,
    ) -> DatabaseUserFixture {
        let email = format!("admin-users-{suffix}@example.com");
        let username = format!("admin-users-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-admin-users-hash', true, false, true, $6, $7)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Text, _>(role.to_owned())
        .bind::<Int4, _>(admin_level)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    pub(crate) async fn store_session(&self, user: &DatabaseUserFixture, sid: &str) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned(), "otp".to_owned(), "mfa".to_owned()],
            pending_mfa: false,
            oidc_sid: Some(format!("oidc-{sid}")),
        };
        valkey_set_ex(
            &self.state.valkey,
            nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
            serde_json::to_string(&payload).expect("session should serialize"),
            self.state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("session should store");
    }

    pub(crate) fn admin_get_request(&self, sid: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::get()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .to_http_request()
    }

    pub(crate) fn admin_post_request(&self, sid: &str, csrf: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::post()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.session.csrf_cookie_name.clone(),
                csrf.to_owned(),
            ))
            .insert_header(("x-csrf-token", csrf))
            .to_http_request()
    }

    pub(crate) async fn load_user(&self, user_id: Uuid) -> DatabaseUserFixture {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        users::table
            .find(user_id)
            .select(DatabaseUserFixture::as_select())
            .first::<DatabaseUserFixture>(&mut conn)
            .await
            .expect("user should be readable")
    }
}

impl LiveAdminUsersFixture {
    pub(crate) async fn audit_count(&self, event: &str, field: &str, value: &str) -> i64 {
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            count: i64,
        }
        let mut conn = get_conn(&self.state.diesel_db).await.unwrap();
        diesel::sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE event_type=$1 AND payload->>$2=$3")
            .bind::<Text,_>(event).bind::<Text,_>(field).bind::<Text,_>(value).get_result::<Count>(&mut conn).await.unwrap().count
    }
}
