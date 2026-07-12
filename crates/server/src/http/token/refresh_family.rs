use diesel::sql_types::BigInt;
use diesel_async::AsyncPgConnection;

use crate::http::prelude::*;

fn advisory_lock_key(token_family_id: Uuid) -> i64 {
    let bytes = token_family_id.as_bytes();
    let high = i64::from_be_bytes(bytes[..8].try_into().expect("UUID has 16 bytes"));
    let low = i64::from_be_bytes(bytes[8..].try_into().expect("UUID has 16 bytes"));
    high ^ low
}

pub(super) async fn lock_token_family(
    conn: &mut AsyncPgConnection,
    token_family_id: Uuid,
) -> diesel::QueryResult<()> {
    diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<BigInt, _>(advisory_lock_key(token_family_id))
        .execute(conn)
        .await?;
    Ok(())
}

pub(super) async fn mark_token_family_reuse(
    conn: &mut AsyncPgConnection,
    tenant_id: Uuid,
    token_family_id: Uuid,
) -> diesel::QueryResult<()> {
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::token_family_id.eq(token_family_id)),
    )
    .set(oauth_tokens::reuse_detected_at.eq(diesel_now))
    .execute(conn)
    .await?;
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::token_family_id.eq(token_family_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(diesel_now))
    .execute(conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_key_is_stable_and_uses_both_uuid_halves() {
        let family = Uuid::parse_str("018f3f91-7912-7d2e-8c71-41f7df28196a").unwrap();
        assert_eq!(advisory_lock_key(family), -8214989690936597436);
        let changed_low = Uuid::parse_str("018f3f91-7912-7d2e-8c71-41f7df28196b").unwrap();
        assert_ne!(advisory_lock_key(family), advisory_lock_key(changed_low));
    }
}
