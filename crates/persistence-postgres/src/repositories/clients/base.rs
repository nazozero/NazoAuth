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
    #[track_caller]
    pub(super) fn connection(
        &self,
    ) -> impl std::future::Future<Output = Result<crate::DbConnection, RepositoryError>> + Send + '_
    {
        let acquire = get_conn(&self.pool);
        async move { acquire.await.map_err(|_| RepositoryError::Unavailable) }
    }
}
