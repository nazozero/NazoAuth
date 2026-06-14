//! Cookie 读写工具。
// 统一会话和 CSRF Cookie 的安全属性与删除策略。

use super::prelude::*;

pub(crate) fn make_cookie(
    name: &str,
    value: &str,
    http_only: bool,
    max_age: u64,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build(name.to_owned(), value.to_owned())
        .path("/")
        .max_age(CookieDuration::seconds(max_age.min(i64::MAX as u64) as i64))
        .same_site(SameSite::Lax)
        .http_only(http_only)
        .secure(secure)
        .finish()
}

pub(crate) fn clear_cookie(name: &str, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build(name.to_owned(), String::new())
        .path("/")
        .same_site(SameSite::Lax)
        .secure(secure)
        .finish();
    cookie.make_removal();
    cookie
}

pub(crate) fn with_cookie_headers(
    mut response: HttpResponse,
    cookies: &[Cookie<'static>],
) -> HttpResponse {
    for cookie in cookies {
        let _ = response.add_cookie(cookie);
    }
    response
}

pub(crate) fn cookie_value(req: &HttpRequest, name: &str) -> Option<String> {
    req.cookie(name).map(|cookie| cookie.value().to_owned())
}

#[cfg(test)]
mod tests;
