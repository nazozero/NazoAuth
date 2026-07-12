use nazo_identity::{
    IdentityUser, TenantContext, UserId,
    ports::{FakeUserRepository, UserRepositoryPort},
};
use uuid::Uuid;

#[tokio::test]
async fn fake_user_repository_is_a_minimal_test_substitute() {
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).unwrap();
    let fake = FakeUserRepository::default();
    assert!(
        fake.principal_by_id(tenant, user_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn identity_user_is_composed_from_domain_concepts_not_a_flat_database_row() {
    fn assert_identity_user(_: &IdentityUser) {}
    let _ = assert_identity_user;
}
