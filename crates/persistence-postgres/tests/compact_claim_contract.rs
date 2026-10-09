use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
#[derive(QueryableByName)]
struct Validity {
    #[diesel(sql_type = sql_types::Bool)]
    valid: bool,
}
async fn accepted(connection: &mut AsyncPgConnection, contract: Value) -> bool {
    sql_query("SELECT public.nazo_refresh_contract_well_formed($1) AS valid")
        .bind::<sql_types::Jsonb, _>(contract)
        .get_result::<Validity>(connection)
        .await
        .unwrap()
        .valid
}
#[tokio::test]
async fn compact_and_retained_contracts_have_distinct_checked_encodings() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    let Ok(url) = url else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires isolated PostgreSQL"
        );
        return;
    };
    nazo_postgres::run_pending_migrations(&url).await.unwrap();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let current = json!({
        "subject":"pairwise", "scopes":["openid"], "audiences":["https://api.example"],
        "authorization_details":[], "authentication_context":{
            "version":2, "issuer":"https://issuer.example", "audience":"client", "auth_time":100,
            "amr":["pwd"], "oidc_sid":"op-session", "nonce":null,"id_token_sid":null,"acr":null,
            "userinfo_claim_requests":[{"name":"email","essential":true,"value":"a@example.test"}],
            "id_token_claim_requests":[]
        }
    });
    assert!(accepted(&mut connection, current.clone()).await);
    let mut legacy = current.clone();
    legacy["authentication_context"]["version"] = json!(1);
    legacy["authentication_context"]["userinfo_claims"] = json!(["email"]);
    legacy["authentication_context"]["id_token_claims"] = json!([]);
    assert!(accepted(&mut connection, legacy.clone()).await);
    let parsed: nazo_auth::RefreshContract = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.authentication_context.version, 1);
    assert_eq!(
        parsed
            .authentication_context
            .userinfo_claim_requests
            .names(),
        ["email"]
    );
    assert!(parsed.authentication_context.userinfo_claim_requests[0].essential);
    for invalid in [
        json!(["email"]),
        json!([false]),
        json!([{}]),
        json!([{"name":false}]),
        json!([{"name":""}]),
        json!([{"name":"email","essential":"true"}]),
        json!([{"name":"email","values":{}}]),
        Value::Null,
    ] {
        let mut contract = current.clone();
        contract["authentication_context"]["userinfo_claim_requests"] = invalid;
        assert!(!accepted(&mut connection, contract).await);
    }
    let mut hybrid = current.clone();
    hybrid["authentication_context"]["userinfo_claims"] = json!(["email"]);
    assert!(!accepted(&mut connection, hybrid).await);
    let mut missing = current.clone();
    missing["authentication_context"]
        .as_object_mut()
        .unwrap()
        .remove("userinfo_claim_requests");
    assert!(!accepted(&mut connection, missing).await);
    let mut unknown = current;
    unknown["authentication_context"]["version"] = json!(3);
    assert!(!accepted(&mut connection, unknown).await);
}
