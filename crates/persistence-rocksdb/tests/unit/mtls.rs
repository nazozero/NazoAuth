use super::*;
use nazo_identity::TenantContext;

use crate::support::clients;

fn material(index: u8) -> PreparedMtlsTrustAnchor {
    let now = Timestamp::now();
    PreparedMtlsTrustAnchor {
        certificate_pem: format!("certificate-{index}\n"),
        certificate_sha256: format!("{index:064x}"),
        subject_dn: format!("CN=certificate-{index}"),
        not_before: now - jiff::SignedDuration::from_secs(60),
        not_after: now + jiff::SignedDuration::from_secs(600),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_managed_anchor_limit_and_client_authority_are_preserved() {
    let path = std::env::temp_dir().join(format!("nazo-rocksdb-mtls-{}", Uuid::new_v4()));
    let store = RocksDb::open(&path).unwrap();
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let mut client = clients::client(tenant, "mtls-client");
    client.require_mtls_bound_tokens = true;
    let client_id = client.id;
    let tx = store.transaction();
    crate::clients::insert_client_tx(&tx, &client, None, None, 0).unwrap();
    let mut ids = Vec::new();
    for i in 0..7 {
        ids.push(insert_managed_tx(&tx, tenant_id, client_id, material(i)).unwrap());
    }
    tx.commit().unwrap();
    let insert = |index| {
        store.run(move |store| {
            let tx = store.transaction();
            let id = insert_managed_tx(&tx, tenant_id, client_id, material(index))?;
            tx.commit().map_err(map_error)?;
            Ok(id)
        })
    };
    let (a, b) = tokio::join!(insert(7), insert(8));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(a.err().or(b.err()), Some(RepositoryError::Conflict));
    let bundle = store
        .active_bundle(tenant.tenant_id, Some(client_id))
        .await
        .unwrap();
    assert_eq!(bundle.lines().count(), 8);
    assert!(
        store
            .by_id(tenant.tenant_id, ids[0])
            .await
            .unwrap()
            .is_none()
    );
    let tx = store.transaction();
    revoke_managed_tx(&tx, tenant_id, ids[0]).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        store
            .active_bundle(tenant.tenant_id, Some(client_id))
            .await
            .unwrap()
            .lines()
            .count(),
        7
    );
    let tx = store.transaction();
    crate::clients::disable_client_tx(&tx, tenant_id, client_id).unwrap();
    tx.commit().unwrap();
    assert!(
        store
            .active_bundle(tenant.tenant_id, None)
            .await
            .unwrap()
            .is_empty()
    );
    drop(store);
    let store = RocksDb::open(&path).unwrap();
    assert!(
        store
            .active_bundle(tenant.tenant_id, None)
            .await
            .unwrap()
            .is_empty()
    );
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}
