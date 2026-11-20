//! Account profile projections and updates use the existing identity contracts.

use nazo_identity::{
    PostalAddress, ProfilePatch, PublicAccount, TenantId, UserId,
    ports::{GrantSummaryRepositoryPort, ProfileRepositoryPort, RepositoryError, RepositoryFuture},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    D1Provider,
    db::DbError,
    persistence::{UserRow, encode},
};

impl ProfileRepositoryPort for D1Provider {
    fn update_profile<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        update: ProfilePatch,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            let address = PostalAddress {
                formatted: update.address_formatted,
                street_address: update.address_street_address,
                locality: update.address_locality,
                region: update.address_region,
                postal_code: update.address_postal_code,
                country: update.address_country,
            };
            let address = (address != PostalAddress::default()).then_some(address);
            // Profile normalization belongs to AccountProfileService. Update only
            // its editable projection in one statement; identity, authorization
            // epoch, avatar and concurrent account changes remain intact.
            let row = self.database.query::<UserRow>(
                "UPDATE nazo_users SET claims=json_set(claims,
                    '$.name',?3,'$.given_name',?4,'$.family_name',?5,
                    '$.middle_name',?6,'$.nickname',?7,'$.profile',?8,
                    '$.website',?9,'$.gender',?10,'$.birthdate',?11,
                    '$.zoneinfo',?12,'$.locale',?13,'$.address',json(?14),
                    '$.phone_number',?15,'$.phone_number_verified',
                        json(CASE WHEN json_extract(claims,'$.phone_number_verified')=1
                            AND json_extract(claims,'$.phone_number') IS ?15
                            THEN 'true' ELSE 'false' END),
                    '$.updated_at',unixepoch()),
                    updated_at=CAST(unixepoch('subsec')*1000000 AS INTEGER)
                 WHERE tenant_id=?1 AND id=?2 AND active=1
                 RETURNING principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at",
                vec![json!(self.tenant_id), json!(user_id.as_uuid()),
                    json!(update.display_name), json!(update.given_name), json!(update.family_name),
                    json!(update.middle_name), json!(update.nickname), json!(update.profile_url),
                    json!(update.website_url), json!(update.gender), json!(update.birthdate),
                    json!(update.zoneinfo), json!(update.locale), json!(encode(&address)?),
                    json!(update.phone_number)],
            ).await?.pop().ok_or(RepositoryError::NotFound)?;
            row.public_account(tenant_id, user_id).map_err(Into::into)
        })
    }
}

impl GrantSummaryRepositoryPort for D1Provider {
    fn authorized_client_count(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            #[derive(Deserialize)]
            struct Count {
                count: i64,
            }
            Ok(self
                .database
                .query::<Count>(
                    "SELECT COUNT(*) AS count FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2",
                    vec![json!(self.tenant_id), json!(user_id)],
                )
                .await?
                .pop()
                .ok_or(DbError::CorruptData)?
                .count)
        })
    }
}
