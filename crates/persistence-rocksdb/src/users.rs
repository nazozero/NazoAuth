//! Account authority is separate from profile and verifier material on hot reads.

use jiff::Timestamp;
use nazo_identity::{
    AccountIdentity, AdminPolicyError, AdminUserUpdateOutcome, AuthenticationIdentity,
    PasswordHash, PostalAddress, Principal, ProfilePatch, PublicAccount, ResolvedAdminUserUpdate,
    SubjectClaims, TenantContext, TenantId, UserId, UserProfile, UserRole, authorize_admin_update,
    authorize_tenant_admin_update,
    ports::{
        AdminUserRepositoryPort, AdminUserUpdate, AvatarRepositoryPort, LoginAccountRepositoryPort,
        LoginAccountState, NewUser, PasskeyAccountRepositoryPort, ProfileRepositoryPort,
        RegistrationAccountRepositoryPort, RepositoryError, RepositoryFuture, SessionAccountPort,
        UserPage, UserRepositoryPort,
    },
};
use nazo_persistence::{AdminIdentityAudit, SecurityAuditEvent};
use rocksdb::{SnapshotWithThreadMode, Transaction, TransactionDB};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    RocksDb,
    audit::append_in_tx,
    db::{key, map_error, put, read, read_snapshot, read_tx},
};

pub(crate) const USER_PRINCIPAL: u8 = 0x10;
pub(crate) const USER_CLAIMS: u8 = 0x11;
pub(crate) const USER_METADATA: u8 = 0x12;
pub(crate) const USER_PASSWORD: u8 = 0x13;
pub(crate) const USER_EMAIL: u8 = 0x14;
pub(crate) const USER_NAME: u8 = 0x15;
pub(crate) const USER_TENANT: u8 = 0x16;
const PROVISION_RECEIPT: u8 = 0x17;
pub(crate) const DELETED_USER: u8 = 0x18;
pub(crate) const USER_CREATED: u8 = 0x19;

pub(crate) fn user_created_key(tenant: Uuid, created: Timestamp, user: Uuid) -> Vec<u8> {
    let mut index = key(
        USER_CREATED,
        tenant,
        &((created.as_microsecond() as u64) ^ (1 << 63)).to_be_bytes(),
    );
    index.extend_from_slice(user.as_bytes());
    index
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AccountMetadata {
    pub mfa_enabled: bool,
    pub avatar_revision: i64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

pub(crate) fn corrupt(message: &'static str) -> RepositoryError {
    RepositoryError::Consistency(message.into())
}

pub(crate) fn read_principal_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
    exclusive: bool,
) -> Result<Option<Principal>, RepositoryError> {
    let principal: Option<Principal> =
        read_tx(tx, &key(USER_PRINCIPAL, tenant, user.as_bytes()), exclusive)?;
    if principal
        .as_ref()
        .is_some_and(|p| p.user_id.as_uuid() != user || p.tenant.tenant_id.as_uuid() != tenant)
    {
        return Err(corrupt("account authority key mismatch"));
    }
    Ok(principal)
}

pub(crate) fn admin_principal_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantContext,
    actor: Uuid,
) -> Result<Principal, RepositoryError> {
    read_principal_tx(tx, tenant.tenant_id.as_uuid(), actor, false)?
        .filter(|p| p.tenant == tenant && p.active && p.admin_level().is_some_and(|l| l > 0))
        .ok_or_else(|| corrupt("administrator is no longer authorized"))
}

pub(crate) fn authorize_admin_tx(
    tx: &Transaction<'_, TransactionDB>,
    audit: &AdminIdentityAudit,
) -> Result<(), RepositoryError> {
    admin_principal_tx(tx, audit.tenant, audit.actor_user_id).map(|_| ())
}

pub(crate) fn public_account(
    principal: Principal,
    claims: SubjectClaims,
    metadata: AccountMetadata,
) -> Result<PublicAccount, RepositoryError> {
    if claims.subject != principal.user_id {
        return Err(corrupt("account claims subject mismatch"));
    }
    Ok(PublicAccount {
        principal,
        account: AccountIdentity {
            username: claims.preferred_username,
            email: claims.email,
            email_verified: claims.email_verified,
            mfa_enabled: metadata.mfa_enabled,
        },
        profile: UserProfile {
            avatar_revision: metadata.avatar_revision,
            display_name: claims.name,
            avatar_url: claims.picture,
            given_name: claims.given_name,
            family_name: claims.family_name,
            middle_name: claims.middle_name,
            nickname: claims.nickname,
            profile_url: claims.profile,
            website_url: claims.website,
            gender: claims.gender,
            birthdate: claims.birthdate,
            zoneinfo: claims.zoneinfo,
            locale: claims.locale,
            address: claims.address.unwrap_or_default(),
            phone_number: claims.phone_number,
            phone_number_verified: claims.phone_number_verified,
        },
        created_at: metadata.created_at,
        updated_at: metadata.updated_at,
    })
}

pub(crate) fn public_account_snapshot(
    snapshot: &SnapshotWithThreadMode<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
) -> Result<Option<PublicAccount>, RepositoryError> {
    let Some(principal) = read_snapshot(snapshot, &key(USER_PRINCIPAL, tenant, user.as_bytes()))?
    else {
        return Ok(None);
    };
    let claims = read_snapshot(snapshot, &key(USER_CLAIMS, tenant, user.as_bytes()))?
        .ok_or_else(|| corrupt("account claims missing"))?;
    let metadata = read_snapshot(snapshot, &key(USER_METADATA, tenant, user.as_bytes()))?
        .ok_or_else(|| corrupt("account metadata missing"))?;
    public_account(principal, claims, metadata).map(Some)
}

pub(crate) fn public_account_tx(
    tx: &Transaction<'_, TransactionDB>,
    principal: Principal,
) -> Result<PublicAccount, RepositoryError> {
    let tenant = principal.tenant.tenant_id.as_uuid();
    let user = principal.user_id.as_uuid();
    let claims = read_tx(tx, &key(USER_CLAIMS, tenant, user.as_bytes()), false)?
        .ok_or_else(|| corrupt("account claims missing"))?;
    let metadata = read_tx(tx, &key(USER_METADATA, tenant, user.as_bytes()), false)?
        .ok_or_else(|| corrupt("account metadata missing"))?;
    public_account(principal, claims, metadata)
}

pub(crate) fn create_user_tx(
    tx: &Transaction<'_, TransactionDB>,
    new_user: NewUser,
    role: UserRole,
) -> Result<PublicAccount, RepositoryError> {
    let tenant = new_user.tenant.tenant_id.as_uuid();
    let email_key = key(
        USER_EMAIL,
        tenant,
        new_user.email.trim().to_lowercase().as_bytes(),
    );
    let name_key = key(USER_NAME, tenant, new_user.username.as_bytes());
    if read_tx::<Uuid>(tx, &email_key, true)?.is_some()
        || read_tx::<Uuid>(tx, &name_key, true)?.is_some()
    {
        return Err(RepositoryError::Conflict);
    }
    let id = Uuid::now_v7();
    let user_id = UserId::new(id).map_err(|_| corrupt("invalid account id"))?;
    let now = Timestamp::now();
    let principal = Principal {
        authorization_epoch: 0,
        user_id,
        tenant: new_user.tenant,
        role,
        active: true,
    };
    let claims = SubjectClaims {
        subject: user_id,
        preferred_username: new_user.username,
        email: new_user.email,
        email_verified: new_user.email_verified,
        name: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        address: None,
        phone_number: None,
        phone_number_verified: false,
        updated_at: now.as_second(),
    };
    let metadata = AccountMetadata {
        mfa_enabled: false,
        avatar_revision: 0,
        created_at: now,
        updated_at: now,
    };
    put(tx, &key(USER_PRINCIPAL, tenant, id.as_bytes()), &principal)?;
    put(tx, &key(USER_CLAIMS, tenant, id.as_bytes()), &claims)?;
    put(tx, &key(USER_METADATA, tenant, id.as_bytes()), &metadata)?;
    put(
        tx,
        &key(USER_PASSWORD, tenant, id.as_bytes()),
        &new_user.password_hash.into_persistence_value(),
    )?;
    put(tx, &email_key, &id)?;
    put(tx, &name_key, &id)?;
    put(tx, &key(USER_TENANT, Uuid::nil(), id.as_bytes()), &tenant)?;
    put(tx, &user_created_key(tenant, now, id), &())?;
    public_account(principal, claims, metadata)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_managed_user_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: TenantContext,
    previous_id: Option<Uuid>,
    username: &str,
    email: &str,
    password_hash: &str,
    email_verified: bool,
    profile: &nazo_persistence::tenant_resources::UserProfileFields,
) -> Result<Uuid, RepositoryError> {
    let tenant_id = tenant.tenant_id.as_uuid();
    let user = if let Some(id) = previous_id {
        if read_tx::<bool>(tx, &key(DELETED_USER, tenant_id, id.as_bytes()), false)?
            .unwrap_or(false)
        {
            return Err(RepositoryError::Conflict);
        }
        let mut principal = read_principal_tx(tx, tenant_id, id, true)?
            .filter(|p| p.tenant == tenant && !p.active && p.role == UserRole::User)
            .ok_or(RepositoryError::Conflict)?;
        let claims_key = key(USER_CLAIMS, tenant_id, id.as_bytes());
        let mut claims: SubjectClaims = read_tx(tx, &claims_key, true)?
            .ok_or_else(|| corrupt("managed account claims missing"))?;
        for (table, value) in [
            (USER_EMAIL, email.trim().to_lowercase()),
            (USER_NAME, username.to_owned()),
        ] {
            let lookup = key(table, tenant_id, value.as_bytes());
            if read_tx::<Uuid>(tx, &lookup, true)?.is_some_and(|owner| owner != id) {
                return Err(RepositoryError::Conflict);
            }
            put(tx, &lookup, &id)?;
        }
        if claims.email.trim().to_lowercase() != email.trim().to_lowercase() {
            tx.delete(key(
                USER_EMAIL,
                tenant_id,
                claims.email.trim().to_lowercase().as_bytes(),
            ))
            .map_err(map_error)?;
        }
        if claims.preferred_username != username {
            tx.delete(key(
                USER_NAME,
                tenant_id,
                claims.preferred_username.as_bytes(),
            ))
            .map_err(map_error)?;
        }
        claims.email = email.into();
        claims.email_verified = email_verified;
        claims.preferred_username = username.into();
        principal.active = true;
        put(
            tx,
            &key(USER_PRINCIPAL, tenant_id, id.as_bytes()),
            &principal,
        )?;
        put(
            tx,
            &key(USER_PASSWORD, tenant_id, id.as_bytes()),
            password_hash,
        )?;
        put(tx, &claims_key, &claims)?;
        id
    } else {
        create_user_tx(
            tx,
            NewUser {
                tenant,
                username: username.into(),
                email: email.into(),
                password_hash: nazo_identity::ports::PasswordHashInput::new(password_hash)
                    .map_err(|_| corrupt("invalid managed password verifier"))?,
                email_verified,
            },
            UserRole::User,
        )?
        .id()
    };
    let claims_key = key(USER_CLAIMS, tenant_id, user.as_bytes());
    let mut claims: SubjectClaims =
        read_tx(tx, &claims_key, true)?.ok_or_else(|| corrupt("managed account claims missing"))?;
    claims.name = profile.display_name.clone();
    claims.given_name = profile.given_name.clone();
    claims.family_name = profile.family_name.clone();
    claims.middle_name = profile.middle_name.clone();
    claims.nickname = profile.nickname.clone();
    claims.profile = profile.profile_url.clone();
    let avatar_changed = claims.picture != profile.avatar_url;
    claims.picture = profile.avatar_url.clone();
    claims.website = profile.website_url.clone();
    claims.gender = profile.gender.clone();
    claims.birthdate = profile.birthdate.clone();
    claims.zoneinfo = profile.zoneinfo.clone();
    claims.locale = profile.locale.clone();
    let address = PostalAddress {
        formatted: profile.address_formatted.clone(),
        street_address: profile.address_street_address.clone(),
        locality: profile.address_locality.clone(),
        region: profile.address_region.clone(),
        postal_code: profile.address_postal_code.clone(),
        country: profile.address_country.clone(),
    };
    claims.address = (address != PostalAddress::default()).then_some(address);
    claims.phone_number = profile.phone_number.clone();
    claims.phone_number_verified = profile.phone_number_verified;
    let metadata_key = key(USER_METADATA, tenant_id, user.as_bytes());
    let mut metadata: AccountMetadata = read_tx(tx, &metadata_key, true)?
        .ok_or_else(|| corrupt("managed account metadata missing"))?;
    if avatar_changed {
        metadata.avatar_revision = metadata
            .avatar_revision
            .checked_add(1)
            .ok_or_else(|| corrupt("avatar revision overflow"))?;
    }
    metadata.updated_at = Timestamp::now();
    claims.updated_at = metadata.updated_at.as_second();
    put(tx, &claims_key, &claims)?;
    put(tx, &metadata_key, &metadata)?;
    Ok(user)
}

pub(crate) fn disable_user_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
) -> Result<bool, RepositoryError> {
    let Some(mut principal) = read_principal_tx(tx, tenant, user, true)?.filter(|p| p.active)
    else {
        return Ok(false);
    };
    principal.active = false;
    principal.authorization_epoch = principal
        .authorization_epoch
        .checked_add(1)
        .ok_or_else(|| corrupt("account epoch exhausted"))?;
    put(
        tx,
        &key(USER_PRINCIPAL, tenant, user.as_bytes()),
        &principal,
    )?;
    crate::tokens::revoke_families(tx, tenant, None, Some(user))?;
    crate::grants::delete_for_user_tx(tx, tenant, user)?;
    crate::digital_credentials::issuance::revoke_for_subject(tx, tenant, user)?;
    touch_account_tx(tx, tenant, user)?;
    Ok(true)
}

fn touch_account_tx(
    tx: &Transaction<'_, TransactionDB>,
    tenant: Uuid,
    user: Uuid,
) -> Result<(), RepositoryError> {
    let claims_key = key(USER_CLAIMS, tenant, user.as_bytes());
    let metadata_key = key(USER_METADATA, tenant, user.as_bytes());
    let mut claims: SubjectClaims =
        read_tx(tx, &claims_key, true)?.ok_or_else(|| corrupt("account claims missing"))?;
    let mut metadata: AccountMetadata =
        read_tx(tx, &metadata_key, true)?.ok_or_else(|| corrupt("account metadata missing"))?;
    metadata.updated_at = Timestamp::now();
    claims.updated_at = metadata.updated_at.as_second();
    put(tx, &claims_key, &claims)?;
    put(tx, &metadata_key, &metadata)
}

impl RocksDb {
    pub async fn account_by_id(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        self.run(move |db| {
            public_account_snapshot(&db.db.snapshot(), tenant.as_uuid(), user.as_uuid())
        })
        .await
    }
    async fn account_by_email(
        &self,
        tenant: TenantId,
        email: &str,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let email = email.trim().to_lowercase();
        self.run(move |db| {
            let snapshot = db.db.snapshot();
            match read_snapshot::<Uuid>(
                &snapshot,
                &key(USER_EMAIL, tenant.as_uuid(), email.as_bytes()),
            )? {
                Some(id) => public_account_snapshot(&snapshot, tenant.as_uuid(), id),
                None => Ok(None),
            }
        })
        .await
    }
    async fn create_account(
        &self,
        user: NewUser,
        audit: Option<(UserId, String)>,
    ) -> Result<PublicAccount, RepositoryError> {
        self.run(move |db| {
            let tx = db.transaction();
            if let Some((actor, _)) = &audit { admin_principal_tx(&tx, user.tenant, actor.as_uuid())?; }
            let account = create_user_tx(&tx, user, UserRole::User)?;
            if let Some((actor, source)) = audit {
                append_in_tx(&tx, &SecurityAuditEvent { event_id: Uuid::new_v4(), event_type: "admin_user_created".into(), event_category: "administration".into(),
                    payload: json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"administration",
                        "tenant_id":account.tenant_id(),"realm_id":account.realm_id(),"organization_id":account.organization_id(),
                        "admin_user_id":actor,"user_id":account.id(),"role":"user","admin_level":0,"is_active":true,"outcome":"success","source_ip_hash":source}), occurred_at: Timestamp::now() })?;
            }
            tx.commit().map_err(map_error)?;
            Ok(account)
        }).await
    }
}

impl SessionAccountPort for RocksDb {
    fn principal_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<Principal>> {
        Box::pin(self.run(move |db| {
            read(
                &db.db,
                &key(
                    USER_PRINCIPAL,
                    tenant_id.as_uuid(),
                    user_id.as_uuid().as_bytes(),
                ),
            )
        }))
    }
    fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(self.account_by_id(tenant_id, user_id))
    }
}
impl UserRepositoryPort for RocksDb {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<Principal>> {
        Box::pin(self.run(move |db| {
            Ok(read::<Principal>(
                &db.db,
                &key(
                    USER_PRINCIPAL,
                    tenant.tenant_id.as_uuid(),
                    user_id.as_uuid().as_bytes(),
                ),
            )?
            .filter(|p| p.tenant == tenant))
        }))
    }
    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<SubjectClaims>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            if !read_snapshot::<Principal>(
                &snapshot,
                &key(
                    USER_PRINCIPAL,
                    tenant.tenant_id.as_uuid(),
                    user_id.as_uuid().as_bytes(),
                ),
            )?
            .is_some_and(|p| p.tenant == tenant)
            {
                return Ok(None);
            }
            read_snapshot(
                &snapshot,
                &key(
                    USER_CLAIMS,
                    tenant.tenant_id.as_uuid(),
                    user_id.as_uuid().as_bytes(),
                ),
            )
        }))
    }
}
impl LoginAccountRepositoryPort for RocksDb {
    fn authentication_by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<AuthenticationIdentity>> {
        let email = email.trim().to_lowercase();
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let tenant = tenant_id.as_uuid();
            let Some(id) =
                read_snapshot::<Uuid>(&snapshot, &key(USER_EMAIL, tenant, email.as_bytes()))?
            else {
                return Ok(None);
            };
            let principal: Principal =
                read_snapshot(&snapshot, &key(USER_PRINCIPAL, tenant, id.as_bytes()))?
                    .ok_or_else(|| corrupt("email index references missing account"))?;
            let password: String =
                read_snapshot(&snapshot, &key(USER_PASSWORD, tenant, id.as_bytes()))?
                    .ok_or_else(|| corrupt("account verifier missing"))?;
            Ok(Some(AuthenticationIdentity {
                user_id: principal.user_id,
                active: principal.active,
                password_hash: PasswordHash::new(password)
                    .map_err(|_| corrupt("invalid account verifier"))?,
            }))
        }))
    }
    fn login_state_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<LoginAccountState>> {
        Box::pin(self.run(move |db| {
            let snapshot = db.db.snapshot();
            let tenant = tenant_id.as_uuid();
            let id = user_id.as_uuid();
            let Some(principal) =
                read_snapshot::<Principal>(&snapshot, &key(USER_PRINCIPAL, tenant, id.as_bytes()))?
            else {
                return Ok(None);
            };
            let metadata: AccountMetadata =
                read_snapshot(&snapshot, &key(USER_METADATA, tenant, id.as_bytes()))?
                    .ok_or_else(|| corrupt("account metadata missing"))?;
            Ok(Some(LoginAccountState {
                authorization_epoch: principal.authorization_epoch,
                active: principal.active,
                mfa_enabled: metadata.mfa_enabled,
            }))
        }))
    }
}
impl RegistrationAccountRepositoryPort for RocksDb {
    fn email_exists<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        let email = email.trim().to_lowercase();
        Box::pin(self.run(move |db| {
            Ok(read::<Uuid>(
                &db.db,
                &key(USER_EMAIL, tenant_id.as_uuid(), email.as_bytes()),
            )?
            .is_some())
        }))
    }
    fn create_user(&self, user: NewUser) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(self.create_account(user, None))
    }
    fn create_user_with_required_audit(
        &self,
        user: NewUser,
        actor_id: UserId,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(self.create_account(user, Some((actor_id, source_ip_hash))))
    }
}
impl PasskeyAccountRepositoryPort for RocksDb {
    fn by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(self.account_by_email(tenant_id, email))
    }
    fn by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(self.account_by_id(tenant_id, user_id))
    }
}
impl nazo_persistence::CibaAccountStore for RocksDb {
    fn by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(self.account_by_email(tenant_id, email))
    }
    fn by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(self.account_by_id(tenant_id, user_id))
    }
}
impl nazo_persistence::Openid4vcSubjectStore for RocksDb {
    fn is_active(&self, tenant_id: TenantId, subject_id: UserId) -> RepositoryFuture<'_, bool> {
        Box::pin(self.run(move |db| {
            Ok(read::<Principal>(
                &db.db,
                &key(
                    USER_PRINCIPAL,
                    tenant_id.as_uuid(),
                    subject_id.as_uuid().as_bytes(),
                ),
            )?
            .is_some_and(|p| p.active))
        }))
    }
}
impl ProfileRepositoryPort for RocksDb {
    fn update_profile<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        update: ProfilePatch,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(self.run(move |db| {
            let tx = db.transaction();
            let tenant = tenant_id.as_uuid();
            let user = user_id.as_uuid();
            let managed = crate::tenant_resources::managed_user_tx(&tx, tenant, user)?;
            let principal = read_principal_tx(&tx, tenant, user, false)?
                .filter(|p| p.active)
                .ok_or(RepositoryError::NotFound)?;
            let claims_key = key(USER_CLAIMS, tenant, user.as_bytes());
            let metadata_key = key(USER_METADATA, tenant, user.as_bytes());
            let mut claims: SubjectClaims = read_tx(&tx, &claims_key, true)?
                .ok_or_else(|| corrupt("account claims missing"))?;
            let mut metadata: AccountMetadata = read_tx(&tx, &metadata_key, true)?
                .ok_or_else(|| corrupt("account metadata missing"))?;
            let address = PostalAddress {
                formatted: update.address_formatted,
                street_address: update.address_street_address,
                locality: update.address_locality,
                region: update.address_region,
                postal_code: update.address_postal_code,
                country: update.address_country,
            };
            let address = (address != PostalAddress::default()).then_some(address);
            if managed
                && (claims.name != update.display_name
                    || claims.given_name != update.given_name
                    || claims.family_name != update.family_name
                    || claims.middle_name != update.middle_name
                    || claims.nickname != update.nickname
                    || claims.profile != update.profile_url
                    || claims.website != update.website_url
                    || claims.gender != update.gender
                    || claims.birthdate != update.birthdate
                    || claims.zoneinfo != update.zoneinfo
                    || claims.locale != update.locale
                    || claims.address != address
                    || claims.phone_number != update.phone_number)
            {
                return Err(RepositoryError::Conflict);
            }
            claims.name = update.display_name;
            claims.given_name = update.given_name;
            claims.family_name = update.family_name;
            claims.middle_name = update.middle_name;
            claims.nickname = update.nickname;
            claims.profile = update.profile_url;
            claims.website = update.website_url;
            claims.gender = update.gender;
            claims.birthdate = update.birthdate;
            claims.zoneinfo = update.zoneinfo;
            claims.locale = update.locale;
            claims.address = address;
            claims.phone_number_verified &= claims.phone_number == update.phone_number;
            claims.phone_number = update.phone_number;
            metadata.updated_at = Timestamp::now();
            claims.updated_at = metadata.updated_at.as_second();
            put(&tx, &claims_key, &claims)?;
            put(&tx, &metadata_key, &metadata)?;
            tx.commit().map_err(map_error)?;
            public_account(principal, claims, metadata)
        }))
    }
}

impl AvatarRepositoryPort for RocksDb {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        expected_url: Option<&'a str>,
        expected_revision: i64,
        avatar_url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        let expected_url = expected_url.map(str::to_owned);
        Box::pin(self.run(move |db| {
            let replay_revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| corrupt("avatar revision overflow"))?;
            let tx = db.transaction();
            let tenant = tenant.as_uuid();
            let user = user.as_uuid();
            let managed = crate::tenant_resources::managed_user_tx(&tx, tenant, user)?;
            let Some(principal) = read_principal_tx(&tx, tenant, user, false)? else {
                return Ok(None);
            };
            let claims_key = key(USER_CLAIMS, tenant, user.as_bytes());
            let metadata_key = key(USER_METADATA, tenant, user.as_bytes());
            let mut claims: SubjectClaims = read_tx(&tx, &claims_key, true)?
                .ok_or_else(|| corrupt("account claims missing"))?;
            let mut metadata: AccountMetadata = read_tx(&tx, &metadata_key, true)?
                .ok_or_else(|| corrupt("account metadata missing"))?;
            if avatar_url.is_some()
                && metadata.avatar_revision == replay_revision
                && claims.picture == avatar_url
            {
                return public_account(principal, claims, metadata).map(Some);
            }
            if metadata.avatar_revision != expected_revision || claims.picture != expected_url {
                return Ok(None);
            }
            if claims.picture != avatar_url {
                if managed {
                    return Err(RepositoryError::Conflict);
                }
                metadata.avatar_revision = replay_revision;
            }
            claims.picture = avatar_url;
            metadata.updated_at = Timestamp::now();
            claims.updated_at = metadata.updated_at.as_second();
            put(&tx, &claims_key, &claims)?;
            put(&tx, &metadata_key, &metadata)?;
            tx.commit().map_err(map_error)?;
            public_account(principal, claims, metadata).map(Some)
        }))
    }
}

fn denial(reason: AdminPolicyError) -> &'static str {
    match reason {
        AdminPolicyError::ActorNotAuthorized => "actor_not_authorized",
        AdminPolicyError::CrossTenant => "cross_tenant",
        AdminPolicyError::SelfElevation => "self_elevation",
        AdminPolicyError::SelfDemotionOrDisable => "self_demotion_or_disable",
        AdminPolicyError::TargetAtOrAboveActor => "target_at_or_above_actor",
        AdminPolicyError::GrantAtOrAboveActor => "grant_at_or_above_actor",
        AdminPolicyError::InvalidRoleLevel => "invalid_role_level",
    }
}

enum AdminChange {
    Local(TenantContext, AdminUserUpdate),
    Tenant(i32),
}
impl RocksDb {
    async fn mutate_admin(
        &self,
        actor_tenant: TenantId,
        actor_id: UserId,
        target_tenant: TenantId,
        target_id: UserId,
        change: AdminChange,
        source: String,
    ) -> Result<AdminUserUpdateOutcome, RepositoryError> {
        self.run(move |db| {
            let tx = db.transaction();
            let target_owner = read_tx::<Uuid>(
                &tx,
                &key(USER_TENANT, Uuid::nil(), target_id.as_uuid().as_bytes()),
                false,
            )?.unwrap_or(target_tenant.as_uuid());
            let managed = crate::tenant_resources::managed_user_tx(&tx, target_owner, target_id.as_uuid())?;
            // The same order covers actor=target and opposing concurrent edits.
            let actor_key = key(USER_PRINCIPAL, actor_tenant.as_uuid(), actor_id.as_uuid().as_bytes());
            let target_key = key(USER_PRINCIPAL, target_owner, target_id.as_uuid().as_bytes());
            let (actor, target): (Option<Principal>, Option<Principal>) = if actor_key <= target_key {
                (read_tx(&tx, &actor_key, true)?, read_tx(&tx, &target_key, true)?)
            } else {
                let target = read_tx(&tx, &target_key, true)?;
                (read_tx(&tx, &actor_key, true)?, target)
            };
            let decision: Result<Option<ResolvedAdminUserUpdate>, AdminPolicyError> = match &change {
                AdminChange::Local(context, update) => match (actor.as_ref().filter(|p| p.tenant == *context), target.as_ref()) {
                    (None, _) => Err(AdminPolicyError::ActorNotAuthorized),
                    (Some(_), None) => Ok(None),
                    (Some(_), Some(target)) if target.tenant != *context => Err(AdminPolicyError::CrossTenant),
                    (Some(actor), Some(target)) => authorize_admin_update(actor, target, update).map(Some),
                },
                AdminChange::Tenant(level) => actor.as_ref().ok_or(AdminPolicyError::ActorNotAuthorized)
                    .and_then(|p| authorize_tenant_admin_update(p, actor_tenant, target_tenant, *level))
                    .map(|()| target.as_ref().filter(|p| p.tenant.tenant_id == target_tenant)
                        .map(|p| ResolvedAdminUserUpdate {
                            role: if *level == 0 { "user" } else { "admin" }.into(),
                            admin_level: *level,
                            active: p.active,
                        })),
            };
            let success = matches!(decision, Ok(Some(_)));
            let reason = match &decision {
                Ok(Some(_)) => "admin_updated",
                Ok(None) => "target_not_found",
                Err(e) => denial(*e),
            };
            let event_type = if matches!(change, AdminChange::Tenant(_)) {
                "system_tenant_admin_updated"
            } else if success {
                "admin_user_updated"
            } else {
                "admin_user_update_denied"
            };
            let resolved = decision.as_ref().ok().and_then(Option::as_ref);
            let event = SecurityAuditEvent {
                event_id: Uuid::new_v4(),
                event_type: event_type.into(),
                event_category: "administration".into(),
                occurred_at: Timestamp::now(),
                payload: json!({
                    "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                    "event_category": "administration",
                    "tenant_id": target_tenant,
                    "control_tenant_id": actor_tenant,
                    "realm_id": target.as_ref().map(|p| p.tenant.realm_id),
                    "organization_id": target.as_ref().map(|p| p.tenant.organization_id),
                    "admin_user_id": actor_id,
                    "actor_user_id": actor_id,
                    "actor_tenant_id": actor.as_ref().map(|p| p.tenant.tenant_id),
                    "user_id": target_id,
                    "target_tenant_id": target_tenant,
                    "target_user_id": target_id,
                    "role": resolved.map(|r| r.role.as_str()),
                    "admin_level": resolved.map(|r| r.admin_level),
                    "is_active": resolved.map(|r| r.active),
                    "outcome": if success { "success" } else { "denied" },
                    "reason": reason,
                    "source_ip_hash": source,
                }),
            };
            let outcome = match decision {
                Err(e) => AdminUserUpdateOutcome::Denied(e),
                Ok(None) => AdminUserUpdateOutcome::TargetNotFound,
                Ok(Some(resolved)) => {
                    let mut target = target.ok_or_else(|| corrupt("target account missing"))?;
                    let role = if resolved.admin_level == 0 {
                        UserRole::User
                    } else {
                        UserRole::Admin { level: u32::try_from(resolved.admin_level).map_err(|_| corrupt("invalid admin level"))? }
                    };
                    if managed && (target.role != role || target.active != resolved.active) {
                        return Err(RepositoryError::Conflict);
                    }
                    let no_op = matches!(change, AdminChange::Local(_, ref update)
                        if update.role.is_none() && update.admin_level.is_none() && update.active.is_none());
                    if !no_op {
                        let deactivated = target.active && !resolved.active;
                        if resolved.active && read_tx::<bool>(&tx, &key(DELETED_USER, target_owner, target_id.as_uuid().as_bytes()), false)?.unwrap_or(false) {
                            return Err(RepositoryError::Conflict);
                        }
                        target.role = role;
                        target.active = resolved.active;
                        if deactivated {
                            target.authorization_epoch = target.authorization_epoch.checked_add(1)
                                .ok_or_else(|| corrupt("account epoch exhausted"))?;
                            crate::tokens::revoke_families(&tx, target_owner, None, Some(target_id.as_uuid()))?;
                            crate::grants::delete_for_user_tx(&tx, target_owner, target_id.as_uuid())?;
                            crate::digital_credentials::issuance::revoke_for_subject(&tx, target_owner, target_id.as_uuid())?;
                        }
                        put(&tx, &target_key, &target)?;
                        touch_account_tx(&tx, target_owner, target_id.as_uuid())?;
                    }
                    AdminUserUpdateOutcome::Updated(Box::new(public_account_tx(&tx, target)?))
                }
            };
            append_in_tx(&tx, &event)?;
            tx.commit().map_err(map_error)?;
            Ok(outcome)
        }).await
    }
}
impl AdminUserRepositoryPort for RocksDb {
    fn page(&self, tenant_id: TenantId, limit: i64, offset: i64) -> RepositoryFuture<'_, UserPage> {
        Box::pin(self.run(move |db| {
            if limit < 0 || offset < 0 {
                return Err(corrupt("negative account page bounds"));
            }
            let snapshot = db.db.snapshot();
            let prefix = key(USER_CREATED, tenant_id.as_uuid(), &[]);
            let mut upper = prefix.clone();
            upper.extend_from_slice(&[u8::MAX; 24]);
            let mut total = 0_i64;
            let mut users = Vec::new();
            let mut rows = snapshot.raw_iterator();
            rows.seek_for_prev(&upper);
            while let Some(k) = rows.key() {
                if !k.starts_with(&prefix) {
                    break;
                }
                if total >= offset && users.len() < limit as usize {
                    let id = Uuid::from_slice(&k[prefix.len() + 8..])
                        .map_err(|_| corrupt("invalid account creation index"))?;
                    users.push(
                        public_account_snapshot(&snapshot, tenant_id.as_uuid(), id)?.ok_or_else(
                            || corrupt("account creation index references missing account"),
                        )?,
                    );
                }
                total += 1;
                rows.prev();
            }
            rows.status().map_err(map_error)?;
            Ok(UserPage { total, users })
        }))
    }
    fn update_authorized_with_required_audit(
        &self,
        tenant: TenantContext,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, AdminUserUpdateOutcome> {
        Box::pin(self.mutate_admin(
            tenant.tenant_id,
            actor_id,
            tenant.tenant_id,
            target_id,
            AdminChange::Local(tenant, update),
            source_ip_hash,
        ))
    }
    fn set_tenant_admin_authorized(
        &self,
        control_tenant_id: TenantId,
        actor_id: UserId,
        target_tenant_id: TenantId,
        target_id: UserId,
        admin_level: i32,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, AdminUserUpdateOutcome> {
        Box::pin(self.mutate_admin(
            control_tenant_id,
            actor_id,
            target_tenant_id,
            target_id,
            AdminChange::Tenant(admin_level),
            source_ip_hash,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct ProvisionReceipt {
    deployment: String,
    tenant: TenantContext,
    user: Uuid,
}
impl nazo_persistence::AdminProvisionStore for RocksDb {
    fn provision(
        &self,
        request: nazo_persistence::AdminProvisionRequest,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::AdminProvisionReceipt, nazo_persistence::AdminProvisionError>,
    > {
        Box::pin(async move {
            use nazo_persistence::AdminProvisionError as E;
            let operation = request.operation_id;
            let deployment = request.deployment_id;
            if operation.is_empty()
                || operation.len() > 128
                || deployment.is_empty()
                || deployment.len() > 128
                || !operation
                    .bytes()
                    .chain(deployment.bytes())
                    .all(|b| b.is_ascii_alphanumeric() || b".:_+-".contains(&b))
            {
                return Err(E::InvalidInput);
            }
            let email = nazo_identity::email::normalize_email_address(&request.email)
                .map_err(|_| E::InvalidInput)?;
            self.run(move |db| {
                let tx = db.transaction();
                let receipt_key = key(PROVISION_RECEIPT, Uuid::nil(), operation.as_bytes());
                if let Some(receipt) = read_tx::<ProvisionReceipt>(&tx, &receipt_key, true)? {
                    if receipt.deployment != deployment || receipt.tenant != request.tenant {
                        return Err(RepositoryError::AlreadyProcessed);
                    }
                    let claims: SubjectClaims = read_tx(
                        &tx,
                        &key(
                            USER_CLAIMS,
                            request.tenant.tenant_id.as_uuid(),
                            receipt.user.as_bytes(),
                        ),
                        false,
                    )?
                    .ok_or_else(|| corrupt("provisioned administrator missing"))?;
                    if claims.email != email {
                        return Err(RepositoryError::AlreadyProcessed);
                    }
                    return Ok(nazo_persistence::AdminProvisionReceipt {
                        operation_id: operation,
                        deployment_id: deployment,
                        user_id: receipt.user,
                        email,
                    });
                }
                let account = create_user_tx(
                    &tx,
                    NewUser {
                        tenant: request.tenant,
                        username: format!("admin_{}", Uuid::now_v7().simple()),
                        email: email.clone(),
                        password_hash: request.password_hash,
                        email_verified: true,
                    },
                    UserRole::Admin { level: 2 },
                )?;
                put(
                    &tx,
                    &receipt_key,
                    &ProvisionReceipt {
                        deployment: deployment.clone(),
                        tenant: request.tenant,
                        user: account.id(),
                    },
                )?;
                append_in_tx(
                    &tx,
                    &SecurityAuditEvent {
                        event_id: Uuid::new_v4(),
                        event_type: "admin_user_created".into(),
                        event_category: "administration".into(),
                        occurred_at: Timestamp::now(),
                        payload: json!({
                            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                            "event_category": "administration",
                            "tenant_id": request.tenant.tenant_id,
                            "user_id": account.id(),
                            "role": "admin",
                            "admin_level": 2,
                            "outcome": "success",
                            "operation_id": operation,
                            "deployment_id": deployment,
                        }),
                    },
                )?;
                tx.commit().map_err(map_error)?;
                Ok(nazo_persistence::AdminProvisionReceipt {
                    operation_id: operation,
                    deployment_id: deployment,
                    user_id: account.id(),
                    email,
                })
            })
            .await
            .map_err(|error| match error {
                RepositoryError::Conflict => E::EmailConflict,
                RepositoryError::AlreadyProcessed => E::OperationConflict,
                RepositoryError::Unavailable => E::Unavailable,
                _ => E::Storage,
            })
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/accounts.rs"]
mod tests;
