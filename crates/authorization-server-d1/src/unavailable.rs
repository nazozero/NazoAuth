//! Unavailable direct avatar-upload state for the D1 adapter.

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
