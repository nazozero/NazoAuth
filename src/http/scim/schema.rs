use crate::http::prelude::*;

pub(super) const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(super) const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub(super) const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub(super) const SCIM_PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub(super) const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub(super) const SCIM_SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
pub(super) const SCIM_RESOURCE_TYPE_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

pub(super) fn scim_user_json(user: UserRow) -> Value {
    scim_base(json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id,
        "userName": user.email,
        "active": user.is_active,
        "name": {
            "formatted": user.display_name,
            "givenName": user.given_name,
            "familyName": user.family_name
        },
        "emails": [{
            "value": user.email,
            "primary": true
        }],
        "meta": {
            "resourceType": "User",
            "created": user.created_at,
            "lastModified": user.updated_at,
            "location": format!("/scim/v2/Users/{}", user.id)
        }
    }))
}

pub(super) fn scim_user_schema() -> Value {
    scim_base(json!({
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": SCIM_USER_SCHEMA,
        "name": "User",
        "description": "Core User",
        "attributes": [
            {"name": "userName", "type": "string", "multiValued": false, "required": true},
            {"name": "active", "type": "boolean", "multiValued": false, "required": false},
            {"name": "name", "type": "complex", "multiValued": false, "required": false},
            {"name": "emails", "type": "complex", "multiValued": true, "required": true}
        ]
    }))
}

pub(super) fn scim_base(value: Value) -> Value {
    value
}

pub(super) fn scim_error(status: StatusCode, scim_type: &str, detail: &str) -> HttpResponse {
    json_response_status(
        status,
        json!({
            "schemas": [SCIM_ERROR_SCHEMA],
            "status": status.as_u16().to_string(),
            "scimType": scim_type,
            "detail": detail
        }),
    )
}
