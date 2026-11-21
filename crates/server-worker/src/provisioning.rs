//! Offline provisioning uses the same registration policy, password hashing,
//! key lifecycle and D1 schema as the Worker. Import the resulting SQL through
//! an authenticated deployment operation, never through a public HTTP route.

use std::{path::Path, sync::Arc};

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_identity::{
    AccountIdentity, Principal, PublicAccount, SubjectClaims, UserId, UserProfile, UserRole,
    ports::SecretHashPort,
};
use nazo_key_management::{ClientRegistrationCrypto, KeyManager, SigningKeyWrappingKeyRing};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    WorkerConfiguration,
    composition::key_settings,
    services::{Passwords, Unavailable},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningInput {
    pub configuration: WorkerConfiguration,
    pub client_secret_pepper: String,
    pub signing_key_id: String,
    pub signing_key_base64: String,
    #[serde(default)]
    pub clients: Vec<nazo_auth::CreateClientRequest>,
    #[serde(default)]
    pub users: Vec<ProvisionedUser>,
    #[serde(default)]
    pub scim_credentials: Vec<ProvisionedScimCredential>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedScimCredential {
    pub token: String,
    pub scopes: Vec<String>,
    pub event_audience: Option<String>,
    pub expires_at: Option<jiff::Timestamp>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedUser {
    pub email: String,
    pub username: String,
    pub password: String,
    /// Explicit offline operator authority; never accepted by registration HTTP.
    pub role: Option<UserRole>,
}

pub async fn provision(path: &Path, input: ProvisioningInput) -> anyhow::Result<Value> {
    let ProvisioningInput {
        configuration,
        client_secret_pepper,
        signing_key_id,
        signing_key_base64,
        clients,
        users,
        scim_credentials,
    } = input;
    let settings = configuration.application(client_secret_pepper.clone())?;
    if configuration.machine_only {
        ensure!(
            users.is_empty(),
            "machine-only Free profile does not provision password users"
        );
        ensure!(
            clients.iter().all(|client| {
                client.client_type == "confidential"
                    && client.redirect_uris.is_empty()
                    && client.grant_types.iter().all(|grant| {
                        nazo_auth::GrantType::try_from(grant.as_str()).is_ok_and(|grant| {
                            settings.protocol.deployment_profile.allows_grant(grant)
                        })
                    })
                    && matches!(
                        client.token_endpoint_auth_method.as_str(),
                        "client_secret_basic" | "client_secret_post" | "private_key_jwt"
                    )
            }),
            "machine-only profile requires confidential service grants without redirects"
        );
    }
    let encoded_key = Zeroizing::new(signing_key_base64);
    let mut key = Zeroizing::new([0_u8; 32]);
    ensure!(
        STANDARD.decode_slice(encoded_key.as_bytes(), key.as_mut_slice())? == 32,
        "wrapping key must decode to 32 bytes"
    );
    let wrapping_keys = SigningKeyWrappingKeyRing::new(signing_key_id, *key, None)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .context("provisioning output must be a new file")?;
    let database = Database::open(path)?;
    database.execute_schema()?;
    let provider = Arc::new(D1Provider::new(database, configuration.tenant.tenant_id));
    provider.initialize_modules(&configuration.modules).await?;
    let keys = KeyManager::load_or_create_database(
        key_settings(),
        None,
        configuration.tenant.tenant_id.as_uuid(),
        provider.signing_key_repository(configuration.tenant.tenant_id.as_uuid()),
        wrapping_keys,
    )
    .await?;
    let policy = nazo_auth::AdminClientPolicy {
        tenant: configuration.tenant,
        pairwise_subject_secret: None,
        client_secret_pepper,
    };
    let crypto = ClientRegistrationCrypto::new(keys);
    let mut issued = Vec::with_capacity(clients.len());
    for request in clients {
        let mut prepared =
            nazo_auth::prepare_client_registration(request, &policy, &Unavailable, &crypto)
                .await
                .map_err(|error| anyhow::anyhow!("client registration failed: {error:?}"))?
                .into_write();
        provider
            .provision_client(&prepared.client, prepared.client_secret_hash.as_deref(), 0)
            .await?;
        issued.push(json!({"client_id": prepared.client.client_id,
            "client_secret": prepared.issued_secret.take_after_commit()}));
    }
    let mut account_ids = Vec::with_capacity(users.len());
    for user in users {
        let email = user.email.trim().to_lowercase();
        ensure!(
            !email.is_empty() && email.contains('@') && !user.username.trim().is_empty(),
            "invalid account identity"
        );
        ensure!(
            user.password.len() >= 12,
            "provisioned account password must contain at least 12 bytes"
        );
        let user_id = UserId::new(uuid::Uuid::new_v4())?;
        let role = user.role.unwrap_or(UserRole::User);
        ensure!(
            !matches!(role, UserRole::Admin { level: 0 }),
            "administrator level must be positive"
        );
        let now = jiff::Timestamp::now();
        let claims: SubjectClaims = serde_json::from_value(json!({
            "subject": user_id, "preferred_username": user.username,
            "email": email, "email_verified": false, "phone_number_verified": false,
            "updated_at": now.as_second()
        }))?;
        let account = PublicAccount {
            principal: Principal {
                authorization_epoch: 0,
                user_id,
                tenant: configuration.tenant,
                role,
                active: true,
            },
            account: AccountIdentity {
                username: user.username,
                email,
                email_verified: false,
                mfa_enabled: false,
            },
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
        };
        let password = Passwords.hash_secret(user.password).await?;
        provider.provision_user(&account, &claims, password).await?;
        account_ids.push(user_id);
    }
    let mut scim_ids = Vec::with_capacity(scim_credentials.len());
    for credential in scim_credentials {
        let token = Zeroizing::new(credential.token);
        ensure!(
            token.len() >= 32,
            "SCIM bearer credential must contain at least 32 bytes"
        );
        let id = uuid::Uuid::new_v4();
        provider
            .provision_scim_credential(
                &nazo_identity::scim::ScimTokenCredential {
                    id,
                    tenant_id: configuration.tenant.tenant_id.as_uuid(),
                    scopes: credential.scopes,
                    event_audience: credential.event_audience,
                },
                &nazo_oauth_server::crypto::blake3_hex(token.as_str()),
                credential.expires_at,
            )
            .await?;
        scim_ids.push(id);
    }
    let dummy = Passwords
        .hash_secret(uuid::Uuid::new_v4().to_string())
        .await?
        .into_persistence_value();
    Ok(
        json!({"clients": issued, "user_ids": account_ids, "scim_credential_ids": scim_ids, "dummy_password_hash": dummy}),
    )
}
