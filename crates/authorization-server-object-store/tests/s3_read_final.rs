use nazo_identity::{
    AvatarContentType, TenantContext,
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
    ).unwrap()
}

fn assert_one_signed_get(server: &ObjectServer) {
    let requests = server.requests();
    assert_eq!(requests.len(), 1, "final read must not issue HEAD");
    assert!(requests[0].starts_with("GET /avatars/avatars/final/"));
    assert!(requests[0].contains("/final-a HTTP/1.1"));
    assert!(requests[0].to_ascii_lowercase().contains("authorization: aws4-hmac-sha256 "));
}

#[tokio::test]
async fn final_read_gets_mime_and_body_from_one_signed_response() {
    let bytes = b"the final response body".to_vec();
    let server = ObjectServer::new(200, Some("image/webp"), bytes.clone());
    let object = store(&server).read_final("final-a").await.unwrap();
    assert_eq!(object.bytes, bytes);
    assert_eq!(object.content_type, AvatarContentType::Webp);
    assert_eq!(object.version, "final-a");
    assert_one_signed_get(&server);
}

#[tokio::test]
async fn final_read_rejects_missing_or_unknown_mime_without_an_extra_request() {
    for mime in [None, Some("text/plain")] {
        let server = ObjectServer::new(200, mime, b"body".to_vec());
        assert_eq!(store(&server).read_final("final-a").await,
            Err(AvatarStorageError::InvalidState));
        assert_one_signed_get(&server);
    }
}

#[tokio::test]
async fn final_read_preserves_status_mapping_and_rejects_unsafe_ids_without_io() {
    for (status, expected) in [
        (404, AvatarStorageError::Missing),
        (409, AvatarStorageError::Conflict),
        (412, AvatarStorageError::Conflict),
        (500, AvatarStorageError::Unavailable("S3 returned HTTP 500".to_owned())),
        (503, AvatarStorageError::Unavailable("S3 returned HTTP 503".to_owned())),
    ] {
        let server = ObjectServer::new(status, Some("image/png"), Vec::new());
        assert_eq!(store(&server).read_final("final-a").await, Err(expected));
        assert_one_signed_get(&server);
    }
    let server = ObjectServer::new(200, Some("image/png"), Vec::new());
    let storage = store(&server);
    for id in ["", "../outside", "a/b", "a?x", "a#x", "a\\b"] {
        assert_eq!(storage.read_final(id).await, Err(AvatarStorageError::InvalidState));
    }
    assert!(server.requests().is_empty());
}
