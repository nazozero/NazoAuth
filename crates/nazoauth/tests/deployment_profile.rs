use nazoauth::integration::route_for_path;

#[test]
fn restricted_profiles_use_the_shared_endpoint_manifest() {
    use http::Method;
    use nazoauth::config::DeploymentProfile;

    for (method, path, passkey, machine) in [
        (
            Method::GET,
            "/.well-known/oauth-authorization-server",
            true,
            true,
        ),
        (
            Method::GET,
            "/.well-known/openid-configuration",
            true,
            false,
        ),
        (Method::GET, "/jwks.json", true, true),
        (Method::POST, "/token", true, true),
        (Method::OPTIONS, "/token", true, true),
        (Method::POST, "/register", true, true),
        (Method::PUT, "/register/client", true, true),
        (Method::GET, "/authorize", true, false),
        (Method::GET, "/userinfo", true, false),
        (Method::POST, "/auth/passkey/begin", true, false),
        (Method::POST, "/auth/passkey/finish", true, false),
        (Method::POST, "/auth/mfa/verify", true, false),
        (Method::OPTIONS, "/auth/mfa/verify", true, false),
        (Method::POST, "/auth/me/mfa/step-up", true, false),
        (
            Method::POST,
            "/auth/me/passkeys/registration/begin",
            true,
            false,
        ),
        (Method::PATCH, "/auth/me", true, false),
        (Method::OPTIONS, "/auth/me", true, false),
        (Method::GET, "/check_session", true, false),
        (Method::POST, "/device_authorization", true, false),
        (Method::GET, "/device/verification", true, false),
        (Method::POST, "/device/decision", true, false),
        (Method::POST, "/auth/login", false, false),
        (Method::OPTIONS, "/auth/login", false, false),
        (Method::POST, "/auth/register", false, false),
        (Method::GET, "/admin/users", false, false),
        (Method::GET, "/auth/me/applications", false, false),
        (Method::POST, "/bc-authorize", false, false),
        (Method::GET, "/scim/v2/ServiceProviderConfig", false, false),
        (
            Method::GET,
            "/.well-known/openid-credential-issuer",
            false,
            false,
        ),
        (Method::POST, "/openid4vp/presentations", false, false),
    ] {
        let route = route_for_path(path).expect(path);
        assert_eq!(
            route.available_in(DeploymentProfile::PasskeyOnly, &method),
            passkey,
            "{method} {path}"
        );
        assert_eq!(
            route.available_in(DeploymentProfile::MachineToMachine, &method),
            machine,
            "{method} {path}"
        );
        assert!(
            route.available_in(DeploymentProfile::Full, &method),
            "{method} {path}"
        );
    }
    let encoded = route_for_path("/auth/%6cogin").expect("canonical login route");
    assert!(!encoded.available_in(DeploymentProfile::PasskeyOnly, &Method::POST));
}

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
