//! 客户端接入申请查询辅助函数。
// 接入申请的列表、搜索和详情 JSON 组装集中在这里。

use super::prelude::*;

fn access_request_search_pattern(q: Option<&str>) -> Option<String> {
    q.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

pub(crate) async fn access_request_count(
    db: &DbPool,
    search: Option<&str>,
    status: Option<AccessRequestStatus>,
) -> anyhow::Result<i64> {
    let mut conn = get_conn(db).await?;
    let mut query = client_access_requests::table
        .inner_join(users::table.on(users::id.eq(client_access_requests::user_id)))
        .into_boxed();
    if let Some(status) = status {
        query = query.filter(client_access_requests::status.eq(status.code()));
    }
    if let Some(pattern) = access_request_search_pattern(search) {
        query = query.filter(
            users::email
                .ilike(pattern.clone())
                .or(client_access_requests::site_name.ilike(pattern.clone()))
                .or(client_access_requests::site_url.ilike(pattern)),
        );
    }
    query
        .select(count(client_access_requests::id))
        .first::<i64>(&mut conn)
        .await
        .map_err(Into::into)
}

pub(crate) async fn access_request_rows(
    db: &DbPool,
    limit: i32,
    offset: i32,
    search: Option<&str>,
    status: Option<AccessRequestStatus>,
) -> anyhow::Result<Vec<Value>> {
    let mut conn = get_conn(db).await?;
    let mut query = client_access_requests::table
        .inner_join(users::table.on(users::id.eq(client_access_requests::user_id)))
        .into_boxed();
    if let Some(status) = status {
        query = query.filter(client_access_requests::status.eq(status.code()));
    }
    if let Some(pattern) = access_request_search_pattern(search) {
        query = query.filter(
            users::email
                .ilike(pattern.clone())
                .or(client_access_requests::site_name.ilike(pattern.clone()))
                .or(client_access_requests::site_url.ilike(pattern)),
        );
    }
    let rows = query
        .select((
            client_access_requests::id,
            client_access_requests::user_id,
            users::email,
            client_access_requests::site_name,
            client_access_requests::site_url,
            client_access_requests::request_description,
            client_access_requests::status,
            client_access_requests::admin_note,
            client_access_requests::approved_client_id,
            client_access_requests::created_at,
            client_access_requests::resolved_at,
        ))
        .order(client_access_requests::created_at.desc())
        .limit(limit as i64)
        .offset(offset as i64)
        .load::<AccessRequestRow>(&mut conn)
        .await?
        .into_iter()
        .map(access_request_json)
        .collect::<Vec<_>>();
    Ok(rows)
}

pub(crate) async fn access_request_by_id(db: &DbPool, id: Uuid) -> anyhow::Result<Option<Value>> {
    let mut conn = get_conn(db).await?;
    Ok(client_access_requests::table
        .inner_join(users::table.on(users::id.eq(client_access_requests::user_id)))
        .filter(client_access_requests::id.eq(id))
        .select((
            client_access_requests::id,
            client_access_requests::user_id,
            users::email,
            client_access_requests::site_name,
            client_access_requests::site_url,
            client_access_requests::request_description,
            client_access_requests::status,
            client_access_requests::admin_note,
            client_access_requests::approved_client_id,
            client_access_requests::created_at,
            client_access_requests::resolved_at,
        ))
        .first::<AccessRequestRow>(&mut conn)
        .await
        .optional()?
        .map(access_request_json))
}

pub(crate) fn access_request_json(row: AccessRequestRow) -> Value {
    json!({
        "id": row.id,
        "user_id": row.user_id,
        "user_email": row.user_email,
        "site_name": row.site_name,
        "site_url": row.site_url,
        "request_description": row.request_description,
        "status": row.status,
        "admin_note": row.admin_note,
        "approved_client_id": row.approved_client_id,
        "created_at": row.created_at,
        "resolved_at": row.resolved_at
    })
}
