use super::*;

#[test]
fn logout_projection_selects_only_its_eleven_facts() {
    let query = oauth_clients::table.select(LogoutClientRecord::as_select());
    let sql = diesel::debug_query::<diesel::pg::Pg, _>(&query).to_string();
    let projection = sql
        .strip_prefix("SELECT ")
        .and_then(|sql| sql.split(" FROM ").next())
        .expect("logout selection should be a SELECT projection");
    let columns: Vec<_> = projection.split(", ").collect();
    let expected: Vec<_> = [
        "id",
        "tenant_id",
        "client_id",
        "is_active",
        "redirect_uris",
        "post_logout_redirect_uris",
        "backchannel_logout_uri",
        "frontchannel_logout_uri",
        "frontchannel_logout_session_required",
        "subject_type",
        "sector_identifier_host",
    ]
    .into_iter()
    .map(|column| format!("\"oauth_clients\".\"{column}\""))
    .collect();
    assert_eq!(columns, expected);
}
