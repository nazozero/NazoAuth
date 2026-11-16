#[test]
fn profile_transports_keep_focused_dependencies() {
    let server_transports = [
        include_str!("../../../../nazoauth/src/endpoints/profile/access_requests.rs"),
        include_str!("../../../../nazoauth/src/endpoints/profile/avatar.rs"),
        include_str!("../../../../nazoauth/src/endpoints/profile/delivery.rs"),
        include_str!("../../../../nazoauth/src/endpoints/profile/federation_links.rs"),
    ]
    .join("\n");
    let account_transport = include_str!("../../../../nazoauth/src/http/profile_account.rs");

    for source in [&server_transports, account_transport] {
        for forbidden in [
            "Data<TestInfrastructure>",
            "nazo_postgres::",
            "nazo_valkey::",
            "diesel::",
            "fred::",
        ] {
            assert!(
                !source.contains(forbidden),
                "profile transport crossed a focused boundary: {forbidden}"
            );
        }
    }
    assert!(
        !server_transports.contains("tokio::fs"),
        "profile transport performs filesystem IO directly"
    );
}

#[path = "profile/mfa_required.rs"]
mod mfa_required;
