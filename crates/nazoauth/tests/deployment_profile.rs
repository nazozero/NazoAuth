use nazoauth::integration::route_for_path;

#[test]
fn deployment_control_routes_follow_the_compiled_capability() {
    for path in [
        "/.well-known/nazoauth-control",
        "/controller-registry/slots",
        "/controller-recovery/challenges",
        "/controller-recovery/recover",
        "/admin/controller-registry/slots",
        "/admin/controller-registry/slots/rotate",
        "/admin/controller-registry/slots/revoke",
        "/admin/controller-registry/approvals",
        "/admin/controller-registry/recovery-root",
        "/admin/controller-registry/recovery-root/approvals",
        "/admin/controller-registry/recovery-root/rotate",
        "/admin/tenants/tenant-id/users/user-id/admin",
    ] {
        assert_eq!(
            route_for_path(path).is_some(),
            cfg!(feature = "deployment-control"),
            "{path}",
        );
    }
}

#[test]
fn shared_tenant_administration_and_protocol_routes_remain_registered() {
    for path in [
        "/admin/users",
        "/admin/clients",
        "/admin/runtime-modules",
        "/authorize",
        "/token",
        "/auth/me/passkeys",
        "/scim/v2/Users",
        "/openid4vci/nonce",
        "/openid4vp/presentations",
    ] {
        assert!(route_for_path(path).is_some(), "{path}");
    }
}
