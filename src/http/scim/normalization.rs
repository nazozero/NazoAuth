use crate::http::{prelude::*, scim::schema::scim_error};

#[derive(Deserialize)]
pub(crate) struct ScimUserRequest {
    #[serde(rename = "userName")]
    pub(super) user_name: Option<String>,
    pub(super) active: Option<bool>,
    pub(super) name: Option<ScimName>,
    pub(super) emails: Option<Vec<ScimEmail>>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct ScimName {
    #[serde(rename = "givenName")]
    pub(super) given_name: Option<String>,
    #[serde(rename = "familyName")]
    pub(super) family_name: Option<String>,
    #[serde(rename = "formatted")]
    pub(super) formatted: Option<String>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct ScimEmail {
    pub(super) value: Option<String>,
    pub(super) primary: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct ScimPatchRequest {
    #[serde(default)]
    pub(super) schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub(super) operations: Vec<ScimPatchOperation>,
}

#[derive(Deserialize)]
pub(crate) struct ScimPatchOperation {
    pub(super) op: String,
    pub(super) path: Option<String>,
    pub(super) value: Value,
}

pub(super) struct NormalizedScimUser {
    pub(super) user_name: String,
    pub(super) email: String,
    pub(super) active: bool,
    pub(super) display_name: Option<String>,
    pub(super) given_name: Option<String>,
    pub(super) family_name: Option<String>,
}

#[derive(Default)]
pub(super) struct ScimPatch {
    pub(super) user_name: Option<String>,
    pub(super) email: Option<String>,
    pub(super) active: Option<bool>,
    pub(super) display_name: Option<String>,
    pub(super) given_name: Option<String>,
    pub(super) family_name: Option<String>,
}

pub(super) fn normalize_scim_user_payload(
    payload: ScimUserRequest,
    require_identity: bool,
) -> Result<NormalizedScimUser, HttpResponse> {
    let user_name = normalize_scim_string(payload.user_name, 120, "userName", require_identity)?;
    let user_name_email = match user_name {
        Some(value) => normalize_email_address(&value).map_err(|_| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "userName must be an email address",
            )
        })?,
        None if require_identity => {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "userName required",
            ));
        }
        None => String::new(),
    };
    let email = primary_email(payload.emails, require_identity)?;
    if require_identity && email != user_name_email {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "primary email must match userName",
        ));
    }
    let name = payload.name;
    Ok(NormalizedScimUser {
        user_name: user_name_email,
        email,
        active: payload.active.unwrap_or(true),
        display_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.formatted.clone()),
            80,
            "name.formatted",
            false,
        )?,
        given_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.given_name.clone()),
            80,
            "name.givenName",
            false,
        )?,
        family_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.family_name.clone()),
            80,
            "name.familyName",
            false,
        )?,
    })
}

pub(super) fn normalize_patch(
    operations: Vec<ScimPatchOperation>,
) -> Result<ScimPatch, HttpResponse> {
    let mut patch = ScimPatch::default();
    if operations.is_empty() {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidSyntax",
            "PATCH Operations required",
        ));
    }
    for operation in operations {
        if !operation.op.eq_ignore_ascii_case("replace") {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "mutability",
                "only replace is supported",
            ));
        }
        let Some(path) = operation.path.as_deref().map(normalize_scim_path) else {
            apply_patch_object(&mut patch, operation.value)?;
            continue;
        };
        match path.as_str() {
            "username" => {
                patch.user_name = Some(required_email_value(operation.value, "userName")?)
            }
            "active" => patch.active = Some(required_bool_value(operation.value, "active")?),
            "name.formatted" => {
                patch.display_name = Some(required_string_value(operation.value, "name.formatted")?)
            }
            "name.givenname" => {
                patch.given_name = Some(required_string_value(operation.value, "name.givenName")?)
            }
            "name.familyname" => {
                patch.family_name = Some(required_string_value(operation.value, "name.familyName")?)
            }
            "emails" => patch.email = Some(primary_email_from_value(operation.value)?),
            _ => {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    "invalidPath",
                    "unsupported path",
                ));
            }
        }
    }
    sync_scim_identity(&mut patch)?;
    Ok(patch)
}

fn apply_patch_object(patch: &mut ScimPatch, value: Value) -> Result<(), HttpResponse> {
    let object = value.as_object().ok_or_else(|| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidSyntax",
            "PATCH value must be object",
        )
    })?;
    if let Some(value) = object.get("userName") {
        patch.user_name = Some(required_email_value(value.clone(), "userName")?);
    }
    if let Some(value) = object.get("active") {
        patch.active = Some(required_bool_value(value.clone(), "active")?);
    }
    if let Some(value) = object.get("name") {
        let name = value.as_object().ok_or_else(|| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "invalidSyntax",
                "name must be object",
            )
        })?;
        if let Some(value) = name.get("formatted") {
            patch.display_name = Some(required_string_value(value.clone(), "name.formatted")?);
        }
        if let Some(value) = name.get("givenName") {
            patch.given_name = Some(required_string_value(value.clone(), "name.givenName")?);
        }
        if let Some(value) = name.get("familyName") {
            patch.family_name = Some(required_string_value(value.clone(), "name.familyName")?);
        }
    }
    if let Some(value) = object.get("emails") {
        patch.email = Some(primary_email_from_value(value.clone())?);
    }
    if let (Some(user_name), Some(email)) = (&patch.user_name, &patch.email)
        && user_name != email
    {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "primary email must match userName",
        ));
    }
    Ok(())
}

fn sync_scim_identity(patch: &mut ScimPatch) -> Result<(), HttpResponse> {
    match (&patch.user_name, &patch.email) {
        (Some(user_name), Some(email)) if user_name != email => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "primary email must match userName",
        )),
        (Some(user_name), None) => {
            patch.email = Some(user_name.clone());
            Ok(())
        }
        (None, Some(email)) => {
            patch.user_name = Some(email.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn normalize_scim_user_filter(
    filter: Option<&str>,
) -> Result<Option<String>, HttpResponse> {
    let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some((field, value)) = filter.split_once(" eq ") else {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidFilter",
            "only eq filters are supported",
        ));
    };
    if !field.trim().eq_ignore_ascii_case("userName") {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidFilter",
            "only userName filters are supported",
        ));
    }
    let value = value.trim();
    if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidFilter",
            "filter value must be quoted",
        ));
    }
    normalize_email_address(&value[1..value.len() - 1])
        .map(Some)
        .map_err(|_| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "invalidFilter",
                "userName filter is invalid",
            )
        })
}

fn primary_email(values: Option<Vec<ScimEmail>>, required: bool) -> Result<String, HttpResponse> {
    let Some(values) = values else {
        return if required {
            Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "email is required",
            ))
        } else {
            Ok(String::new())
        };
    };
    let selected = values
        .iter()
        .find(|email| email.primary.unwrap_or(false))
        .or_else(|| values.as_slice().first())
        .and_then(|email| email.value.as_deref());
    let Some(value) = selected else {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "email value is required",
        ));
    };
    normalize_email_address(value)
        .map_err(|_| scim_error(StatusCode::BAD_REQUEST, "invalidValue", "email is invalid"))
}

fn primary_email_from_value(value: Value) -> Result<String, HttpResponse> {
    let emails = serde_json::from_value::<Vec<ScimEmail>>(value).map_err(|_| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "emails must be an array",
        )
    })?;
    primary_email(Some(emails), true)
}

fn normalize_scim_string(
    value: Option<String>,
    max_bytes: usize,
    field: &str,
    required: bool,
) -> Result<Option<String>, HttpResponse> {
    let value = value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    match value {
        Some(value) if value.len() <= max_bytes => Ok(Some(value)),
        Some(_) => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} too long"),
        )),
        None if required => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} required"),
        )),
        None => Ok(None),
    }
}

fn required_string_value(value: Value, field: &str) -> Result<String, HttpResponse> {
    normalize_scim_string(value.as_str().map(ToOwned::to_owned), 120, field, true)?
        .ok_or_else(|| scim_error(StatusCode::BAD_REQUEST, "invalidValue", "value required"))
}

fn required_email_value(value: Value, field: &str) -> Result<String, HttpResponse> {
    let value = required_string_value(value, field)?;
    normalize_email_address(&value).map_err(|_| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} must be an email address"),
        )
    })
}

fn required_bool_value(value: Value, field: &str) -> Result<bool, HttpResponse> {
    value.as_bool().ok_or_else(|| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} must be boolean"),
        )
    })
}

fn normalize_scim_path(value: &str) -> String {
    value.trim().replace(' ', "").to_ascii_lowercase()
}
