use diesel::sql_types::BigInt;
use diesel_async::AsyncPgConnection;

use crate::http::prelude::*;

pub(super) const LOST_REFRESH_TOKEN_RETRY_SECONDS: i64 = 60;

pub(super) fn within_lost_refresh_token_retry_window(
    revoked_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    let elapsed = now.signed_duration_since(revoked_at);
    elapsed >= Duration::zero() && elapsed <= Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS)
}

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

pub(super) async fn lost_response_successor(
    conn: &mut AsyncPgConnection,
    token: &TokenRow,
    client_id: Uuid,
    now: DateTime<Utc>,
) -> diesel::QueryResult<Option<TokenRow>> {
    let Some(revoked_at) = token.revoked_at else {
        return Ok(None);
    };
    if !within_lost_refresh_token_retry_window(revoked_at, now) {
        return Ok(None);
    }

    let reuse_count = oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(token.tenant_id))
        .filter(oauth_tokens::token_family_id.eq(token.token_family_id))
        .filter(oauth_tokens::reuse_detected_at.is_not_null())
        .select(diesel::dsl::count_star())
        .first::<i64>(conn)
        .await?;
    if reuse_count != 0 {
        return Ok(None);
    }

    let mut successors = oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(token.tenant_id))
        .filter(oauth_tokens::token_family_id.eq(token.token_family_id))
        .filter(oauth_tokens::client_id.eq(client_id))
        .filter(oauth_tokens::rotated_from_id.eq(token.id))
        .filter(oauth_tokens::dpop_jkt.is_not_distinct_from(token.dpop_jkt.as_deref()))
        .filter(oauth_tokens::mtls_x5t_s256.is_not_distinct_from(token.mtls_x5t_s256.as_deref()))
        .filter(oauth_tokens::revoked_at.is_null())
        .filter(oauth_tokens::expires_at.gt(now))
        .select(TokenRow::as_select())
        .limit(2)
        .load::<TokenRow>(conn)
        .await?;
    if successors.len() == 1 {
        Ok(successors.pop())
    } else {
        Ok(None)
    }
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

    #[test]
    fn lost_response_window_is_inclusive_and_rejects_future_timestamps() {
        let now = Utc::now();
        assert!(within_lost_refresh_token_retry_window(now, now));
        assert!(within_lost_refresh_token_retry_window(
            now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS),
            now
        ));
        assert!(!within_lost_refresh_token_retry_window(
            now - Duration::seconds(LOST_REFRESH_TOKEN_RETRY_SECONDS) - Duration::milliseconds(1),
            now
        ));
        assert!(!within_lost_refresh_token_retry_window(
            now + Duration::milliseconds(1),
            now
        ));
    }
}
