use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use crate::settings::Settings;

use crate::test_support::valkey::valkey_set_ex;

use chrono::{Duration, Utc};

use serde_json::Value;

fn parse_consent_payload(raw: Option<String>) -> Option<ConsentPayload> {
    raw.and_then(|value| serde_json::from_str::<ConsentPayload>(&value).ok())
}
