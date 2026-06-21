use super::*;

#[test]
fn cookies_preserve_configured_secure_attribute() {
    let cookie = make_cookie("sid", "value", true, 60, true);
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));

    let cookie = clear_cookie("sid", true);
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
}
