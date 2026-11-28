use super::*;
use nazo_identity::{OrganizationId, RealmId, TenantContext, TenantId};

fn binding(host: &str) -> TenantDirectoryBinding {
    TenantDirectoryBinding {
        tenant: TenantContext {
            tenant_id: TenantId::new(uuid::Uuid::from_u128(1)).unwrap(),
            realm_id: RealmId::new(uuid::Uuid::from_u128(2)).unwrap(),
            organization_id: OrganizationId::new(uuid::Uuid::from_u128(3)).unwrap(),
        },
        issuer: format!("https://{host}"),
        external_host: host.to_owned(),
        runtime_revision: 1,
    }
}

#[test]
fn authority_selection_keeps_the_actual_host_and_canonicalizes_aliases() {
    for (host, authorities) in [
        (
            "tenant.example",
            vec![
                "tenant.example",
                "tenant.example:443",
                "tenant.example:",
                "Tenant.Example.:8443",
            ],
        ),
        (
            "[2001:db8::1]",
            vec!["[2001:db8::1]", "[2001:0db8::1]:8443", "[2001:db8::1]:"],
        ),
        ("127.0.0.1", vec!["127.0.0.1", "127.1:8000"]),
    ] {
        let registry = test_support::registry(binding(host));
        for authority in authorities {
            assert_eq!(
                registry
                    .resolve(authority, Some(host))
                    .unwrap()
                    .binding
                    .external_host,
                host
            );
        }
    }
}

#[test]
fn invalid_authority_unknown_hosts_and_sni_mismatches_never_select_a_tenant() {
    let registry = test_support::registry(binding("tenant.example"));
    for authority in [
        "",
        "unknown.example",
        "a@tenant.example",
        "tenant.example/path",
        "tenant.example?x",
        "tenant.example#x",
        "tenant.example\\x",
        " tenant.example",
        "tenant.example ",
        "tenant.example:bad",
        "tenant.example:443:443",
        "[::1]bad",
        "[::1]:bad",
        ":443",
    ] {
        assert!(matches!(
            registry.resolve(authority, None),
            Err(http::StatusCode::NOT_FOUND)
        ));
    }
    assert!(matches!(
        registry.resolve("tenant.example", Some("other.example")),
        Err(http::StatusCode::MISDIRECTED_REQUEST)
    ));
}

#[test]
fn authenticated_server_name_accepts_aliases_and_rejects_other_authorities() {
    let registry = test_support::registry(binding("tenant.example"));
    for server_name in [
        "tenant.example",
        "Tenant.Example",
        "tenant.example.",
        "TENANT.EXAMPLE.",
    ] {
        assert!(
            registry
                .resolve("tenant.example", Some(server_name))
                .is_ok()
        );
    }
    for server_name in [
        "other.example",
        "",
        "tenant.example:443",
        "a@tenant.example",
        "tenant.example/path",
    ] {
        assert!(matches!(
            registry.resolve("tenant.example", Some(server_name)),
            Err(http::StatusCode::MISDIRECTED_REQUEST)
        ));
    }
}

#[test]
fn canonical_authority_host_borrows_the_original_request_bytes() {
    for authority in ["tenant.example", "tenant.example:443", "[2001:db8::1]:8443"] {
        let host = authority_host(authority).unwrap();
        assert_eq!(host.as_ptr(), authority.as_ptr());
    }
}

#[test]
fn close_withdraws_tenants_and_prevents_future_publication() {
    let registry = test_support::registry(binding("tenant.example"));
    let retained = registry.load();
    let retired = registry.close();
    assert!(Arc::ptr_eq(&retained, &retired));
    assert!(registry.load().by_host.is_empty());
    assert!(registry.replace(retained).is_err());
    assert!(registry.require_mount_paths(&[]).is_err());
}

#[test]
fn namespace_syntax_is_checked_before_the_first_tenant_exists() {
    let registry = TenantRuntimeRegistry::empty();
    for path in ["api", "/api?x", "/api#x"] {
        assert!(registry.require_mount_paths(&[path]).is_err());
    }
    registry.require_mount_paths(&["/api", "/api/"]).unwrap();
    assert_eq!(
        registry.state.publication.lock().unwrap().occupied_paths,
        vec!["/api"]
    );
}
