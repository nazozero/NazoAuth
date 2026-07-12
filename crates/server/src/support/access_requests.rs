//! 客户端接入申请查询辅助函数。
// 接入申请的列表、搜索和详情 JSON 组装集中在这里。

use super::prelude::*;

pub(crate) async fn access_request_count(
    db: &DbPool,
    search: Option<&str>,
    status: Option<AccessRequestStatus>,
) -> anyhow::Result<i64> {
    nazo_postgres::AccessRequestRepository::new(db.clone())
        .count(search, status.map(AccessRequestStatus::code))
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
    let rows = nazo_postgres::AccessRequestRepository::new(db.clone())
        .page(
            i64::from(limit),
            i64::from(offset),
            search,
            status.map(AccessRequestStatus::code),
        )
        .await?
        .into_iter()
        .map(access_request_json)
        .collect::<Vec<_>>();
    Ok(rows)
}

pub(crate) async fn access_request_by_id(db: &DbPool, id: Uuid) -> anyhow::Result<Option<Value>> {
    Ok(nazo_postgres::AccessRequestRepository::new(db.clone())
        .by_id(id)
        .await?
        .map(access_request_json))
}

pub(crate) fn access_request_json(row: nazo_postgres::AccessRequestProjection) -> Value {
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

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/access_requests.rs"]
mod tests;
