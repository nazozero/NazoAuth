use diesel::{QueryableByName, sql_query, sql_types::Text};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

const UP: &str =
    include_str!("../../../migrations/20260712000050_social_federation_provider_type/up.sql");
const DOWN: &str =
    include_str!("../../../migrations/20260712000050_social_federation_provider_type/down.sql");

#[derive(QueryableByName)]
struct ProviderType {
    #[diesel(sql_type = Text)]
    provider_type: String,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI migration tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[tokio::test]
async fn social_provider_type_migration_preserves_existing_rows_and_has_safe_down_policy() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("social_provider_type_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE external_identity_links (
                provider_type TEXT NOT NULL,
                CONSTRAINT ck_external_identity_links_provider_type
                    CHECK (provider_type IN ('oidc', 'saml'))
            );
            INSERT INTO external_identity_links (provider_type) VALUES ('oidc'), ('saml');
            "#
        ))
        .await
        .expect("baseline schema should create");

    connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(UP).await
        })
        .await
        .expect("up migration should succeed");
    sql_query("INSERT INTO external_identity_links (provider_type) VALUES ('oauth2_social')")
        .execute(&mut connection)
        .await
        .expect("up migration should allow social links");
    let provider_types =
        sql_query("SELECT provider_type FROM external_identity_links ORDER BY provider_type")
            .load::<ProviderType>(&mut connection)
            .await
            .expect("provider rows should remain readable")
            .into_iter()
            .map(|row| row.provider_type)
            .collect::<Vec<_>>();
    assert_eq!(provider_types, ["oauth2_social", "oidc", "saml"]);

    let down_with_social = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(DOWN).await
        })
        .await;
    assert!(
        down_with_social.is_err(),
        "down migration must fail rather than discard existing social links"
    );
    sql_query("DELETE FROM external_identity_links WHERE provider_type = 'oauth2_social'")
        .execute(&mut connection)
        .await
        .expect("operator cleanup policy should be representable");
    connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(DOWN).await
        })
        .await
        .expect("down migration should succeed after social links are handled");
    assert!(
        sql_query("INSERT INTO external_identity_links (provider_type) VALUES ('oauth2_social')")
            .execute(&mut connection)
            .await
            .is_err(),
        "down migration must restore the baseline provider constraint"
    );
    let baseline =
        sql_query("SELECT provider_type FROM external_identity_links ORDER BY provider_type")
            .load::<ProviderType>(&mut connection)
            .await
            .expect("baseline provider rows should survive down migration")
            .into_iter()
            .map(|row| row.provider_type)
            .collect::<Vec<_>>();
    assert_eq!(baseline, ["oidc", "saml"]);

    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}
