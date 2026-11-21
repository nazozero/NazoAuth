//! Disabled tenant-directory and direct avatar-upload ports for the single-tenant host.

pub(crate) struct Unavailable;

impl nazo_identity::ports::AvatarUploadStatePort for Unavailable {
    fn create<'a>(
        &'a self,
        _authorization: &'a nazo_identity::ports::AvatarUploadAuthorization,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn claim<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _lease_until: jiff::Timestamp,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::AvatarUploadClaim> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn record_candidate<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _staged_version: &'a str,
        _final_object_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn complete<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _final_object_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn release<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::TenantDirectoryStore for Unavailable {
    fn current_revision(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<u64, nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn load_active(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_identity::TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn find_active_binding(
        &self,
        _tenant_id: nazo_identity::TenantId,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            Option<nazo_identity::TenantDirectoryBinding>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}
