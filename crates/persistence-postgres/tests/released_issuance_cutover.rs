use diesel::{
    QueryableByName, sql_query,
    sql_types::{Bool, Text},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

const CUTOVER: &str =
    include_str!("../../../migrations/20260913000000_released_issuance_cutover/up.sql");
const LEGACY: &[&str] = &[
    include_str!("support/fixtures/issuance-v0.2.16/20260805000500_token_issuance_saga.sql"),
    include_str!("support/fixtures/issuance-v0.2.16/20260808000100_token_issuance_owner_claim.sql"),
    include_str!(
        "support/fixtures/issuance-v0.2.16/20260814000200_token_issuance_subject_ownership.sql"
    ),
    include_str!("support/fixtures/issuance-v0.2.16/20260906000100_atomic_token_issuance.sql"),
    include_str!("support/fixtures/issuance-v0.2.16/cleanup.sql"),
];

#[derive(QueryableByName)]
struct Flag {
    #[diesel(sql_type = Bool)]
    value: bool,
}
#[derive(QueryableByName)]
struct Value {
    #[diesel(sql_type = Text)]
    value: String,
}

async fn migrate(owner: &mut AsyncPgConnection) -> Result<(), diesel::result::Error> {
    owner
        .transaction(async |connection| connection.batch_execute(CUTOVER).await)
        .await
}

#[tokio::test]
async fn released_receipts_preserve_fences_retention_and_cleanup_acl() {
    let base = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL")
        .expect("released-schema cutover requires isolated PostgreSQL");
    let suffix = Uuid::now_v7().simple().to_string();
    let database = format!("released_issuance_{suffix}");
    let role = format!("cleanup_reader_{suffix}");
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("CREATE ROLE {role} NOLOGIN"))
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&database);
    let mut owner = AsyncPgConnection::establish(url.as_str()).await.unwrap();
    owner.batch_execute("CREATE TABLE tenants(id UUID PRIMARY KEY); CREATE TABLE users(id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id), UNIQUE(id,tenant_id)); CREATE TABLE oauth_clients(id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id), UNIQUE(id,tenant_id)); CREATE TABLE oauth_tokens(id UUID PRIMARY KEY,rotated_from_id UUID); INSERT INTO tenants VALUES('00000000-0000-0000-0000-000000000001'); INSERT INTO users VALUES('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001'); INSERT INTO oauth_clients VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001');").await.unwrap();
    for sql in LEGACY {
        owner.batch_execute(sql).await.unwrap();
    }
    owner.batch_execute(&format!("REVOKE ALL ON FUNCTION nazo_oauth_cleanup_expired_security_state() FROM PUBLIC; GRANT EXECUTE ON FUNCTION nazo_oauth_cleanup_expired_security_state() TO {role} WITH GRANT OPTION")).await.unwrap();
    owner.batch_execute("INSERT INTO oauth_token_issuances(issuance_id,tenant_id,client_id,user_id,grant_key_blake3,request_digest,expires_at) VALUES('00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002',repeat('a',64),repeat('b',64),CURRENT_TIMESTAMP + INTERVAL '1 hour')").await.unwrap();
    let error = migrate(&mut owner).await.unwrap_err().to_string();
    assert!(
        error.contains("lacks terminal ownership/replay evidence"),
        "{error}"
    );
    assert!(sql_query("SELECT NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='oauth_token_issuances'::regclass AND attname='retain_until' AND NOT attisdropped) AND EXISTS(SELECT 1 FROM oauth_token_issuances WHERE access_token_jti IS NULL) AS value").get_result::<Flag>(&mut owner).await.unwrap().value);
    owner.batch_execute("UPDATE oauth_token_issuances SET access_token_jti='legacy-jti-1',access_token_expires_at=CURRENT_TIMESTAMP+INTERVAL '3 hours',response_ciphertext=decode('0102','hex'),response_digest=repeat('c',64),response_envelope_version='v1',response_key_id='legacy-key'").await.unwrap();
    let error = migrate(&mut owner).await.unwrap_err().to_string();
    assert!(
        error.contains("drain live legacy response receipts"),
        "{error}"
    );
    assert!(
        sql_query(
            "SELECT response_ciphertext=decode('0102','hex') AS value FROM oauth_token_issuances"
        )
        .get_result::<Flag>(&mut owner)
        .await
        .unwrap()
        .value
    );
    owner.batch_execute("UPDATE oauth_token_issuances SET response_ciphertext=NULL,response_digest=NULL,response_envelope_version=NULL,response_key_id=NULL; INSERT INTO oauth_token_issuances(issuance_id,tenant_id,client_id,user_id,grant_key_blake3,request_digest,access_token_jti,access_token_expires_at,expires_at) VALUES('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002',repeat('d',64),repeat('e',64),'legacy-jti-2',CURRENT_TIMESTAMP+INTERVAL '2 hours',CURRENT_TIMESTAMP+INTERVAL '5 hours')").await.unwrap();
    let before = sql_query("SELECT jsonb_agg(jsonb_build_object('id',issuance_id,'tenant',tenant_id,'client',client_id,'user',user_id,'key',grant_key_blake3,'jti',access_token_jti,'access_expiry',access_token_expires_at,'retain_until',GREATEST(expires_at,access_token_expires_at)) ORDER BY issuance_id)::text AS value FROM oauth_token_issuances").get_result::<Value>(&mut owner).await.unwrap().value;
    migrate(&mut owner).await.unwrap();
    let after = sql_query("SELECT jsonb_agg(jsonb_build_object('id',issuance_id,'tenant',tenant_id,'client',client_id,'user',user_id,'key',encode(single_use_key_blake3,'hex'),'jti',access_token_jti,'access_expiry',access_token_expires_at,'retain_until',retain_until) ORDER BY issuance_id)::text AS value FROM oauth_token_issuances").get_result::<Value>(&mut owner).await.unwrap().value;
    assert_eq!(
        before, after,
        "receipt identities, owners, replay digests and both original deadlines must survive"
    );
    let args = sql_query("SELECT proargnames::text AS value FROM pg_proc WHERE oid='nazo_oauth_cleanup_expired_security_state()'::regprocedure").get_result::<Value>(&mut owner).await.unwrap().value;
    assert!(args.starts_with("{deleted_issuances,"), "{args}");
    assert!(sql_query("SELECT EXISTS(SELECT 1 FROM pg_proc proc CROSS JOIN LATERAL aclexplode(proc.proacl) acl WHERE proc.oid='nazo_oauth_cleanup_expired_security_state()'::regprocedure AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1) AND acl.privilege_type='EXECUTE' AND acl.is_grantable) AND NOT EXISTS(SELECT 1 FROM pg_proc proc CROSS JOIN LATERAL aclexplode(proc.proacl) acl WHERE proc.oid='nazo_oauth_cleanup_expired_security_state()'::regprocedure AND acl.grantee=0) AS value").bind::<Text,_>(&role).get_result::<Flag>(&mut owner).await.unwrap().value);
    // An already-upgraded schema must remain a no-op, including the later
    // boolean cleanup entry point; never resurrect the retired overload.
    owner.batch_execute("DROP FUNCTION nazo_oauth_cleanup_expired_security_state(); CREATE FUNCTION nazo_oauth_cleanup_expired_security_state(BOOLEAN) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'").await.unwrap();
    migrate(&mut owner).await.unwrap();
    assert!(sql_query("SELECT to_regprocedure('public.nazo_oauth_cleanup_expired_security_state()') IS NULL AND to_regprocedure('public.nazo_oauth_cleanup_expired_security_state(boolean)') IS NOT NULL AS value").get_result::<Flag>(&mut owner).await.unwrap().value);
    // Resume a failed upgrade after refresh migration retired oauth_tokens.
    // The released receipt table may still require conversion at that point.
    owner.batch_execute("DROP TABLE oauth_token_issuances; DROP TABLE oauth_tokens; DROP FUNCTION nazo_oauth_cleanup_expired_security_state(BOOLEAN)").await.unwrap();
    for sql in LEGACY {
        owner.batch_execute(sql).await.unwrap();
    }
    owner.batch_execute("INSERT INTO oauth_token_issuances(issuance_id,tenant_id,client_id,user_id,grant_key_blake3,request_digest,access_token_jti,access_token_expires_at,expires_at) VALUES('00000000-0000-0000-0000-000000000012','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002',repeat('f',64),repeat('a',64),'resume-jti',CURRENT_TIMESTAMP+INTERVAL '2 hours',CURRENT_TIMESTAMP+INTERVAL '1 hour')").await.unwrap();
    migrate(&mut owner).await.unwrap();
    assert!(sql_query("SELECT to_regclass('public.oauth_tokens') IS NULL AND EXISTS(SELECT 1 FROM oauth_token_issuances WHERE access_token_jti='resume-jti' AND retain_until=access_token_expires_at) AS value").get_result::<Flag>(&mut owner).await.unwrap().value);
    drop(owner);
    admin
        .batch_execute(&format!("DROP DATABASE {database} WITH(FORCE)"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("DROP ROLE {role}"))
        .await
        .unwrap();
}
