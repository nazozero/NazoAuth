use crate::domain::DatabaseUserFixture;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::http::sessions::SessionPayload;

use crate::settings::Settings;

use crate::test_support::valkey::valkey_set_ex;

use actix_web::http::header;

use chrono::Utc;

use nazo_identity::AccessRequestStatus;

fn my_access_requests_response(rows: Vec<nazo_identity::AccessRequest>) -> HttpResponse {
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| user_access_request_json(row, None))
        .collect();
    access_request_items_response(items)
}
