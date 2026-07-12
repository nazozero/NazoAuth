#[must_use]
pub fn valid_authentication_metadata(
    auth_time: i64,
    amr: &[String],
    oidc_sid: Option<&str>,
    now: i64,
) -> bool {
    auth_time > 0
        && auth_time <= now.saturating_add(30)
        && !amr.is_empty()
        && oidc_sid.is_some_and(|sid| !sid.trim().is_empty())
}

pub fn add_amr(amr: &mut Vec<String>, value: &str) {
    if !amr.iter().any(|method| method == value) {
        amr.push(value.to_owned());
    }
}
