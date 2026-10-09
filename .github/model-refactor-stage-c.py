# One-off branch input, removed after producing the verified source commit.
from pathlib import Path
import re
R=Path.cwd()
def put(path,content):
    p=R/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
put('crates/authorization-server-core/src/claim_selection.rs', '''//! One claim-request authority per response target.
//!
//! Older encoded authorizations carried both bare names and full requests. Only
//! decoding needs both: a full request wins for the same name, so a legacy bare
//! name cannot remove its essential/value constraints. New encodings carry only
//! the full requests. These values do not prescribe a storage backend.
use std::ops::{Deref, DerefMut};
use serde::{Deserialize, Serialize};
use crate::OidcClaimRequest;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(from = "LegacyUserinfoSelection")]
pub struct UserinfoClaimRequests {
    userinfo_claim_requests: Vec<OidcClaimRequest>,
}
#[derive(Default, Deserialize)]
struct LegacyUserinfoSelection {
    #[serde(default)]
    userinfo_claims: Vec<String>,
    #[serde(default)]
    userinfo_claim_requests: Vec<OidcClaimRequest>,
}
impl From<LegacyUserinfoSelection> for UserinfoClaimRequests {
    fn from(legacy: LegacyUserinfoSelection) -> Self {
        Self { userinfo_claim_requests: merge_legacy_names(legacy.userinfo_claims, legacy.userinfo_claim_requests) }
    }
}
impl From<Vec<OidcClaimRequest>> for UserinfoClaimRequests {
    fn from(userinfo_claim_requests: Vec<OidcClaimRequest>) -> Self { Self { userinfo_claim_requests } }
}
impl Deref for UserinfoClaimRequests {
    type Target = Vec<OidcClaimRequest>;
    fn deref(&self) -> &Self::Target { &self.userinfo_claim_requests }
}
impl DerefMut for UserinfoClaimRequests {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.userinfo_claim_requests }
}
impl UserinfoClaimRequests {
    /// Presentation-only projection; never another stored or writable authority.
    #[must_use]
    pub fn names(&self) -> Vec<&str> { self.iter().map(|request| request.name.as_str()).collect() }
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(from = "LegacyIdTokenSelection")]
pub struct IdTokenClaimRequests {
    id_token_claim_requests: Vec<OidcClaimRequest>,
}
#[derive(Default, Deserialize)]
struct LegacyIdTokenSelection {
    #[serde(default)]
    id_token_claims: Vec<String>,
    #[serde(default)]
    id_token_claim_requests: Vec<OidcClaimRequest>,
}
impl From<LegacyIdTokenSelection> for IdTokenClaimRequests {
    fn from(legacy: LegacyIdTokenSelection) -> Self {
        Self { id_token_claim_requests: merge_legacy_names(legacy.id_token_claims, legacy.id_token_claim_requests) }
    }
}
impl From<Vec<OidcClaimRequest>> for IdTokenClaimRequests {
    fn from(id_token_claim_requests: Vec<OidcClaimRequest>) -> Self { Self { id_token_claim_requests } }
}
impl Deref for IdTokenClaimRequests {
    type Target = Vec<OidcClaimRequest>;
    fn deref(&self) -> &Self::Target { &self.id_token_claim_requests }
}
impl DerefMut for IdTokenClaimRequests {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.id_token_claim_requests }
}
impl IdTokenClaimRequests {
    /// Presentation-only projection; never another stored or writable authority.
    #[must_use]
    pub fn names(&self) -> Vec<&str> { self.iter().map(|request| request.name.as_str()).collect() }
}
fn merge_legacy_names(names: Vec<String>, mut requests: Vec<OidcClaimRequest>) -> Vec<OidcClaimRequest> {
    for name in names {
        if !requests.iter().any(|request| request.name == name) { requests.push(OidcClaimRequest::named(name)); }
    }
    requests
}
''')
put('crates/authorization-server-core/tests/claim_selection.rs', '''use nazo_auth::{Claims, IdTokenClaimRequests, OidcClaimRequest, UserinfoClaimRequests};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Debug, Deserialize, Serialize)]
struct SelectionPair {
    #[serde(flatten)]
    userinfo: UserinfoClaimRequests,
    #[serde(flatten)]
    id_token: IdTokenClaimRequests,
}
#[test]
fn legacy_names_are_read_without_weakening_full_requests_or_crossing_targets() {
    let decoded: SelectionPair = serde_json::from_value(json!({
        "userinfo_claims": ["email", "name", "email"],
        "userinfo_claim_requests": [{"name":"email","essential":true,"value":"allowed@example.test"}],
        "id_token_claims": ["sid"],
        "id_token_claim_requests": [{"name":"acr","essential":true,"values":["urn:acr:2"]}]
    })).unwrap();
    assert_eq!(decoded.userinfo.names(), ["email", "name"]);
    assert!(decoded.userinfo[0].essential);
    assert_eq!(decoded.userinfo[0].value, Some(json!("allowed@example.test")));
    assert_eq!(decoded.userinfo[1], OidcClaimRequest::named("name"));
    assert_eq!(decoded.id_token.names(), ["acr", "sid"]);
    assert_eq!(decoded.id_token[0].values, [json!("urn:acr:2")]);
    let encoded = serde_json::to_value(&decoded).unwrap();
    assert!(encoded.get("userinfo_claims").is_none());
    assert!(encoded.get("id_token_claims").is_none());
    assert_eq!(encoded.as_object().unwrap().len(), 2);
    let round_trip: SelectionPair = serde_json::from_value(encoded).unwrap();
    assert_eq!(round_trip.userinfo, decoded.userinfo);
    assert_eq!(round_trip.id_token, decoded.id_token);
}
#[test]
fn current_and_legacy_fields_reject_malformed_inputs() {
    for invalid in [
        json!({"userinfo_claims": [false]}),
        json!({"userinfo_claim_requests": ["email"]}),
        json!({"userinfo_claim_requests": [{"name":"email","essential":"true"}]}),
        json!({"id_token_claims": null}),
        json!({"id_token_claim_requests": [{"name":"sid","values":false}]}),
    ] {
        assert!(serde_json::from_value::<SelectionPair>(invalid.clone()).is_err(), "{invalid}");
    }
}
#[test]
fn old_access_token_claim_selection_is_not_lost_on_decode() {
    let wire = json!({
        "iss":"https://issuer.example", "sub":"pairwise-user", "tenant_id":"tenant",
        "subject_type":"user", "aud":"https://issuer.example/userinfo", "client_id":"client",
        "scope":"openid", "token_use":"access", "jti":"token", "iat":100, "nbf":100,"exp":200,
        "userinfo_claims":["email","name"],
        "userinfo_claim_requests":[{"name":"email","essential":true,"values":["a@example.test"]}]
    });
    let claims: Claims = serde_json::from_value(wire).unwrap();
    assert_eq!(claims.userinfo_claim_requests.names(), ["email", "name"]);
    assert_eq!(claims.userinfo_claim_requests[0].values, [json!("a@example.test")]);
    let new_wire: Value = serde_json::to_value(claims).unwrap();
    assert!(new_wire.get("userinfo_claims").is_none());
}
''')
full=(R/'migrations/20260926000100_refresh_state_minimal/up.sql').read_text()
m=re.search(r'CREATE FUNCTION nazo_refresh_contract_well_formed\(contract JSONB\).*?\n\$\$;',full,re.S);assert m
old=m[0].replace('CREATE FUNCTION nazo_refresh_contract_well_formed','CREATE OR REPLACE FUNCTION public.nazo_refresh_contract_well_formed',1)
new=old.replace("(contract #>> '{authentication_context,version}')::INT = 1", "(contract #>> '{authentication_context,version}')::INT IN (1, 2)")
start=new.index("       AND jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claims'");end=new.index(',\n       FALSE',start)
check=r'$.type() == "array" && !exists($[*] ? (@.type() != "object" || !exists(@.name) || @.name.type() != "string" || @.name like_regex "^\\s*$" || (exists(@.essential) && @.essential.type() != "boolean") || (exists(@.values) && @.values.type() != "array")))'
clause='''       AND CASE (contract #>> '{authentication_context,version}')::INT
         WHEN 1 THEN
           jsonb_path_match(contract -> 'authentication_context' -> 'userinfo_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
           AND jsonb_path_match(contract -> 'authentication_context' -> 'id_token_claims', '$.type() == "array" && !exists($[*] ? (@.type() != "string"))')
         WHEN 2 THEN
           NOT ((contract -> 'authentication_context') ? 'userinfo_claims')
           AND NOT ((contract -> 'authentication_context') ? 'id_token_claims')
'''
for name in ['userinfo_claim_requests','id_token_claim_requests']:
    clause+=f"           AND jsonb_path_match(contract -> 'authentication_context' -> '{name}', '{check}')\n"
clause+='         ELSE FALSE\n       END'
new=new[:start]+clause+new[end:]
D='migrations/20261009000100_compact_oidc_claim_selections'
put(D+'/up.sql', '''-- New refresh contracts encode each claim request once (version 2).
-- Version 1 remains readable, with its original content key and original JSON.
-- Never rewrite active contracts or recompute referenced historical digests.
'''+new+'\n')
put(D+'/down.sql', '''-- An older binary cannot read compact contracts. Do not destroy authorization
-- evidence or expand/rekey active contracts to manufacture a downgrade.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.oauth_refresh_contracts
               WHERE contract #>> '{authentication_context,version}' = '2') THEN
        RAISE EXCEPTION 'compact refresh contracts still exist; downgrade is unsafe'
            USING ERRCODE = '55006';
    END IF;
END;
$$;
'''+old+'\n')
put('crates/persistence-postgres/migration-head.txt',D.split('/')[-1]+'\n')
f=R/'crates/persistence-postgres/tests/support/mod.rs';s=f.read_text().replace('[&str; 21]','[&str; 22]').replace('    "20261006000200",\n','    "20261006000200",\n    "20261009000100",\n').replace('    include_str!("../../../../migrations/20261006000200_audit_fresh_claim_finalization/up.sql"),','    include_str!("../../../../migrations/20261006000200_audit_fresh_claim_finalization/up.sql"),\n    include_str!("../../../../migrations/20261009000100_compact_oidc_claim_selections/up.sql"),');f.write_text(s)
f=R/'crates/persistence-postgres/tests/refresh_authority.rs';s=f.read_text().replace('.bind::<sql_types::Jsonb, _>(serde_json::to_value(context).unwrap())', '''.bind::<sql_types::Jsonb, _>({
        // Historical fixture: encode the actual pre-cutover version, not the
        // current compact Rust writer. Only the migration computes its key.
        let mut legacy = serde_json::to_value(context).unwrap();
        legacy["version"] = json!(1);
        legacy["userinfo_claims"] = json!([]);
        legacy["id_token_claims"] = json!([]);
        legacy
    })''',1)
needle='''    // Populate the genuine preceding schema. No proof count can distinguish a
    // fresh family from one whose old opaque-token associations were trimmed.
''';assert needle in s
s=s.replace(needle, '''    // Only the unrelated claim-encoding validator is brought forward so the
    // current writer can seed this fixture. All retention tables/functions
    // remain at the genuine pre-retention-cutover state under test.
    let compact = migrations.iter().find(|path| path.file_name().unwrap()
        == "20261009000100_compact_oidc_claim_selections").unwrap();
    apply_migration(&mut connection, compact).await;
    // No proof count can distinguish a fresh family from one whose old
    // opaque-token associations were trimmed.
''');f.write_text(s)
put('crates/persistence-postgres/tests/compact_claim_contract.rs', '''use diesel::{QueryableByName, sql_query, sql_types};
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
        .get_result::<Validity>(connection).await.unwrap().valid
}
#[tokio::test]
async fn compact_and_retained_contracts_have_distinct_checked_encodings() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    let Ok(url) = url else {
        assert!(std::env::var_os("CI").is_none(), "CI requires isolated PostgreSQL");
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
    assert_eq!(parsed.authentication_context.userinfo_claim_requests.names(), ["email"]);
    assert!(parsed.authentication_context.userinfo_claim_requests[0].essential);
    for invalid in [
        json!(["email"]), json!([false]), json!([{}]), json!([{"name":false}]),
        json!([{"name":""}]), json!([{"name":"email","essential":"true"}]),
        json!([{"name":"email","values":{}}]), Value::Null,
    ] {
        let mut contract = current.clone();
        contract["authentication_context"]["userinfo_claim_requests"] = invalid;
        assert!(!accepted(&mut connection, contract).await);
    }
    let mut hybrid = current.clone();
    hybrid["authentication_context"]["userinfo_claims"] = json!(["email"]);
    assert!(!accepted(&mut connection, hybrid).await);
    let mut missing = current.clone();
    missing["authentication_context"].as_object_mut().unwrap().remove("userinfo_claim_requests");
    assert!(!accepted(&mut connection, missing).await);
    let mut unknown = current;
    unknown["authentication_context"]["version"] = json!(3);
    assert!(!accepted(&mut connection, unknown).await);
}
''')
