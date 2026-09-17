//! Tenant signing keys and their atomically persisted OpenID4VC authority material.

use std::collections::BTreeSet;

use anyhow::{Context, bail};
use nazo_auth::SigningPurpose;
use nazo_key_management::signing_algorithm_from_name;

use crate::{config::ConfigSource, settings::Settings};

mod openid4vc_material;

pub(crate) use openid4vc_material::{
    MdocCrlSource, MdocManagementAction, operator_manage_mdoc, signed_mdoc_crl,
};
use openid4vc_material::{database_certificate_profile, generate_local_with_database_manager};

#[derive(Debug)]
struct GenerateLocalKeyOptions {
    alg: nazo_crypto::jwt::Algorithm,
    purposes: BTreeSet<SigningPurpose>,
}

pub(crate) async fn remove_tenant_material(
    tenant_id: nazo_identity::TenantId,
) -> anyhow::Result<()> {
    let config = ConfigSource::load_without_secret_values()?;
    let data_dir = config.persistent_path("DATA_DIR", Some(crate::config::DEFAULT_DATA_DIR))?;
    let tenants_dir = data_dir.join("tenants");
    let tenant_dir = tenants_dir.join(tenant_id.as_uuid().to_string());
    match tokio::fs::symlink_metadata(&tenant_dir).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("tenant material path must be a real directory")
        }
        Ok(_) => tokio::fs::remove_dir_all(&tenant_dir)
            .await
            .with_context(|| format!("failed to remove tenant material {}", tenant_dir.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect tenant material {}", tenant_dir.display())),
    }
}

fn parse_generate_local(
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<GenerateLocalKeyOptions> {
    let alg = signing_algorithm_from_name(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {algorithm}"))?;
    let mut parsed = BTreeSet::new();
    for name in purposes {
        let purpose = SigningPurpose::from_name(name)
            .ok_or_else(|| anyhow::anyhow!("unsupported signing purpose {name}"))?;
        if !parsed.insert(purpose) {
            bail!("duplicate signing purpose {name}");
        }
    }
    if parsed.is_empty() {
        bail!("generate-local requires non-empty purposes");
    }
    if parsed.iter().any(|purpose| {
        !matches!(
            purpose,
            SigningPurpose::Credential | SigningPurpose::PresentationRequest
        )
    }) {
        bail!("generate-local purposes are restricted to credential,presentation_request");
    }
    Ok(GenerateLocalKeyOptions {
        alg,
        purposes: parsed,
    })
}

async fn database_key_manager_for_tenant(
    config: &ConfigSource,
    settings: &Settings,
    tenant_id: nazo_identity::TenantId,
    persistence: &dyn crate::operator_task::OperatorPersistence,
) -> anyhow::Result<nazo_key_management::KeyManager> {
    nazo_key_management::KeyManager::load_or_create_database(
        settings.key_settings(),
        settings.external_key_signer(),
        tenant_id.as_uuid(),
        persistence.signing_key_repository(tenant_id.as_uuid()),
        crate::settings::signing_key_wrapping_key_ring(config)?,
    )
    .await
}

pub(crate) async fn operator_list_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
) -> anyhow::Result<String> {
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager =
        database_key_manager_for_tenant(config, &settings, binding.tenant.tenant_id, persistence)
            .await?;
    let _ = manager.database_list_keys().await?;
    manager.database_revision().await
}

pub(crate) async fn operator_validate_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
) -> anyhow::Result<String> {
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager =
        database_key_manager_for_tenant(config, &settings, binding.tenant.tenant_id, persistence)
            .await?;
    manager.database_validate().await?;
    manager.database_revision().await
}

pub(crate) async fn operator_register_external_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
    kid: &str,
    algorithm: &str,
    key_ref: &str,
    public_jwk_bytes: &[u8],
) -> anyhow::Result<String> {
    let algorithm = signing_algorithm_from_name(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported signing alg {algorithm}"))?;
    let public_jwk = serde_json::from_slice(public_jwk_bytes)
        .context("failed to parse mounted external public JWK")?;
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager =
        database_key_manager_for_tenant(config, &settings, binding.tenant.tenant_id, persistence)
            .await?;
    manager
        .database_register_external(nazo_key_management::ExternalKeyRegistration {
            kid: kid.to_owned(),
            algorithm,
            key_ref: key_ref.to_owned(),
            public_jwk,
        })
        .await?;
    manager.database_revision().await
}

pub(crate) async fn operator_generate_local_database_for_tenant(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
    algorithm: &str,
    purposes: &[String],
) -> anyhow::Result<(String, String, Option<String>)> {
    let options = parse_generate_local(algorithm, purposes)?;
    let settings = Settings::from_directory_binding(config, binding)?;

    let manager =
        database_key_manager_for_tenant(config, &settings, binding.tenant.tenant_id, persistence)
            .await?;
    let profile = database_certificate_profile(binding, config, &options)?;
    let kid = generate_local_with_database_manager(&manager, profile.as_ref(), options).await?;
    let state = manager.database_openid4vc_state().await?;
    Ok((
        kid,
        state.revision.to_string(),
        state
            .material
            .map(|material| material.public.certificate_chain_pem),
    ))
}

#[cfg(test)]
#[path = "../../tests/unit/keyctl/shared.rs"]
mod shared;

#[cfg(test)]
#[path = "../../tests/unit/keyctl/operator.rs"]
mod tests;
