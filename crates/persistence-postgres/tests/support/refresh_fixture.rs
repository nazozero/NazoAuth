//! Shared fixture construction for the durable refresh source contract.
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, OnceLock};

use nazo_auth::{NewRefreshToken, RefreshContract, RefreshTokenCommit};
use nazo_postgres::{TokenRepository, create_pool};
use uuid::Uuid;

static PRESENTATIONS: OnceLock<Mutex<HashMap<Uuid, String>>> = OnceLock::new();

#[derive(Clone)]
pub struct RefreshFixture {
    pub token: NewRefreshToken,
    pub contract: RefreshContract,
}

impl RefreshFixture {
    pub fn new(token: NewRefreshToken, contract: RefreshContract) -> Self {
        PRESENTATIONS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(token.member_id, token.raw_token.clone());
        Self { token, contract }
    }

    pub async fn into_commit(self) -> RefreshTokenCommit {
        let Some(parent) = self.token.rotated_from_id else {
            return RefreshTokenCommit::IssueNew {
                token: self.token,
                contract: self.contract,
            };
        };
        let raw = PRESENTATIONS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .get(&parent)
            .expect("the source fixture must have registered its raw token")
            .clone();
        let url = std::env::var("NAZO_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("test database URL");
        let source = TokenRepository::new(create_pool(&url, 2).unwrap())
            .by_raw_refresh_token(self.token.tenant_id, &raw)
            .await
            .unwrap()
            .expect("the source presentation must still resolve when preparing issuance");
        RefreshTokenCommit::UseExisting {
            authority: source.authority(),
            rotation: Some(self.token),
        }
    }
}

impl Deref for RefreshFixture {
    type Target = NewRefreshToken;
    fn deref(&self) -> &Self::Target {
        &self.token
    }
}
impl DerefMut for RefreshFixture {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.token
    }
}
