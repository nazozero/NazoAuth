use nazo_identity::{
    TenantContext,
    ports::{AvatarDirectUploadPort, AvatarStorageError},
};
use nazo_oauth_server_object_store::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};

mod support;
use support::http_object::ObjectServer;

fn store(server: &ObjectServer) -> S3AvatarObjectStore {
    S3AvatarObjectStore::new(
        S3AvatarObjectStoreConfig {
            endpoint: server.endpoint(),
            region: "us-east-1".to_owned(),
            bucket: "avatars".to_owned(),
            access_key: "fixture-access".to_owned(),
            secret_key: "fixture-secret".to_owned(),
            path_style: true,
        },
        TenantContext::default_system().tenant_id,
    )
    .unwrap()
}

#[tokio::test]
async fn staged_read_uses_one_get_snapshot_for_version_length_and_bounded_body() {
    let server = ObjectServer::new_with_etag(
        200,
        Some("image/png"),
        vec![1, 2, 3],
        Some("\"snapshot-version\""),
    );
    let staged = store(&server).read_staged("staging-a", 3).await.unwrap();
    assert_eq!(staged.bytes, vec![1, 2, 3]);
    assert_eq!(staged.version, "\"snapshot-version\"");
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /avatars/avatars/staging/"));
    assert!(requests[0].contains("/staging-a HTTP/1.1"));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: aws4-hmac-sha256")
    );
    assert!(!requests[0].to_ascii_lowercase().contains("if-match:"));
}

#[tokio::test]
async fn staged_read_rejects_oversize_or_unversioned_snapshots_without_another_request() {
    for (body, version, limit) in [
        (vec![1, 2, 3], Some("\"snapshot-version\""), 2),
        (vec![1, 2], None, 2),
    ] {
        let server = match version {
            Some(version) => {
                ObjectServer::new_with_etag(200, Some("image/png"), body, Some(version))
            }
            None => ObjectServer::new(200, Some("image/png"), body),
        };
        assert!(matches!(
            store(&server).read_staged("staging-a", limit).await,
            Err(AvatarStorageError::InvalidState)
        ));
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET "));
    }
}
