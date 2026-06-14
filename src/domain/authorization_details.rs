//! RFC 9396-style authorization details helpers.

use serde::Deserialize;
use serde_json::Value;

const AUTHORIZATION_DETAILS_MAX_BYTES: usize = 16 * 1024;
pub(crate) const SUPPORTED_AUTHORIZATION_DETAILS_TYPES: &[&str] =
    &["account_information", "payment_initiation"];

pub(crate) fn parse_authorization_details(raw: Option<&str>) -> Result<Value, ()> {
    let Some(raw) = raw else {
        return Ok(Value::Array(Vec::new()));
    };
    if raw.len() > AUTHORIZATION_DETAILS_MAX_BYTES {
        return Err(());
    }
    let value: Value = serde_json::from_str(raw).map_err(|_| ())?;
    validate_authorization_details(&value)?;
    Ok(value)
}

pub(crate) fn empty_authorization_details() -> Value {
    Value::Array(Vec::new())
}

pub(crate) fn deserialize_authorization_details<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    normalize_authorization_details(value)
        .map_err(|()| serde::de::Error::custom("authorization_details must be a valid JSON array"))
}

pub(crate) fn normalize_authorization_details(value: Value) -> Result<Value, ()> {
    match value {
        Value::Null => Ok(empty_authorization_details()),
        Value::Object(object) if object.is_empty() => Ok(empty_authorization_details()),
        other => {
            validate_authorization_details(&other)?;
            Ok(other)
        }
    }
}

pub(crate) fn canonical_authorization_details(value: &Value) -> Result<String, ()> {
    validate_authorization_details(value)?;
    serde_json::to_string(value).map_err(|_| ())
}

pub(crate) fn authorization_details_empty(value: &Value) -> bool {
    value.as_array().is_none_or(Vec::is_empty)
}

pub(crate) fn high_risk_authorization_details(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            let Some(object) = item.as_object() else {
                return false;
            };
            let type_ = object.get("type").and_then(Value::as_str).unwrap_or("");
            type_.contains("payment")
                || object
                    .get("actions")
                    .and_then(Value::as_array)
                    .is_some_and(|actions| {
                        actions.iter().filter_map(Value::as_str).any(|action| {
                            matches!(
                                action,
                                "write" | "create" | "update" | "delete" | "transfer" | "payment"
                            )
                        })
                    })
        })
    })
}

fn validate_authorization_details(value: &Value) -> Result<(), ()> {
    let Some(items) = value.as_array() else {
        return Err(());
    };
    if items.len() > 32 {
        return Err(());
    }
    for item in items {
        let Some(object) = item.as_object() else {
            return Err(());
        };
        let Some(type_) = object.get("type").and_then(Value::as_str) else {
            return Err(());
        };
        if type_.trim().is_empty() || type_.len() > 256 {
            return Err(());
        }
        if !SUPPORTED_AUTHORIZATION_DETAILS_TYPES.contains(&type_) {
            return Err(());
        }
        if let Some(actions) = object.get("actions") {
            let Some(actions) = actions.as_array() else {
                return Err(());
            };
            if actions.is_empty() || actions.len() > 32 {
                return Err(());
            }
            for action in actions {
                let Some(action) = action.as_str() else {
                    return Err(());
                };
                if action.trim().is_empty() || action.len() > 128 {
                    return Err(());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
