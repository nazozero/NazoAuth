use nazo_identity::ports::RepositoryError;

use crate::{DbPool, get_conn};

#[derive(Clone)]
pub struct OAuthClientRepository {
    pool: DbPool,
}

impl OAuthClientRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl OAuthClientRepository {
    pub(super) async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}
