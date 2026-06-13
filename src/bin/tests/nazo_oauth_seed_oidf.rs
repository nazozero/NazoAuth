use super::*;

#[test]
fn callback_uris_include_local_and_official_suite_bases() {
    let urls = suite_base_urls("https://nginx:8443/");

    assert!(urls.contains(&"https://nginx:8443".to_owned()));
    assert!(urls.contains(&"https://www.certification.openid.net".to_owned()));
    let callbacks = callback_uris(&urls, "local-nazo-oauth-oidf");
    assert!(
        callbacks
            .iter()
            .any(|value| value == "https://nginx:8443/test/a/local-nazo-oauth-oidf/callback")
    );
    assert!(callbacks.iter().any(|value| value
        == "https://www.certification.openid.net/test/a/local-nazo-oauth-oidf/callback"));
}
