use super::*;

fn store(endpoint: &str, path_style: bool) -> S3AvatarObjectStore {
    S3AvatarObjectStore::new(
        S3AvatarObjectStoreConfig {
            endpoint: endpoint.to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "avatar.bucket".to_owned(),
            access_key: "access".to_owned(),
            secret_key: "secret".to_owned(),
            path_style,
        },
        TenantId::new(uuid::Uuid::now_v7()).expect("tenant"),
    )
    .expect("valid config")
}

#[test]
fn path_style_preserves_endpoint_prefix_without_double_slash() {
    let url =
        store("https://objects.example.test/prefix/", true).object_url("avatars/staging/object-id");
    assert_eq!(
        url.as_str(),
        "https://objects.example.test/prefix/avatar.bucket/avatars/staging/object-id"
    );
}

#[test]
fn virtual_host_style_moves_bucket_into_host() {
    let url = store("https://objects.example.test/", false).object_url("avatars/final/object-id");
    assert_eq!(
        url.as_str(),
        "https://avatar.bucket.objects.example.test/avatars/final/object-id"
    );
}

#[test]
fn tenant_binding_shares_the_connection_and_keeps_distinct_object_namespaces() {
    let first = store("https://objects.example.test/prefix/", true);
    let second = first
        .client
        .for_tenant(TenantId::new(uuid::Uuid::now_v7()).unwrap());
    assert!(Arc::ptr_eq(&first.client, &second.client));
    assert_ne!(
        first.staging_key("object-id").unwrap(),
        second.staging_key("object-id").unwrap()
    );
    assert_ne!(
        first.final_key("object-id").unwrap(),
        second.final_key("object-id").unwrap()
    );
    assert_eq!(first.client.endpoint, second.client.endpoint);
}
