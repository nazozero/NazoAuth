//! CBOR Tag 1004 — Full-date string (RFC 8943).
//!
//! Used in mdoc for date-only fields: `birth_date`, `issue_date`, `expiry_date`.
//! Format: `YYYY-MM-DD` (RFC 3339 full-date).

use crate::error::MdocError;
use ciborium::Value;

/// CBOR Tag number for full-date strings.
pub const TAG_FULL_DATE: u64 = 1004;

/// A full-date value (RFC 8943, CBOR Tag 1004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullDate(pub String);

impl FullDate {
    /// Create a new FullDate from a string.
    pub fn new(date: &str) -> Self {
        Self(date.to_string())
    }

    /// Get the date string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encode as a CBOR Tag 1004 value.
    pub fn to_cbor(&self) -> Value {
        Value::Tag(TAG_FULL_DATE, Box::new(Value::Text(self.0.clone())))
    }

    /// Decode from a CBOR value (Tag 1004 or plain text).
    pub fn from_cbor(value: &Value) -> Result<Self, MdocError> {
        match value {
            Value::Tag(TAG_FULL_DATE, inner) => match inner.as_ref() {
                Value::Text(s) => Ok(Self(s.clone())),
                _ => Err(MdocError::Cbor(
                    "Tag 1004 inner value is not text".to_string(),
                )),
            },
            Value::Text(s) => Ok(Self(s.clone())),
            _ => Err(MdocError::Cbor(format!(
                "expected Tag 1004 or text, got {:?}",
                value
            ))),
        }
    }
}

impl std::fmt::Display for FullDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_date_round_trip() {
        let date = FullDate::new("1990-01-15");
        let cbor = date.to_cbor();
        let decoded = FullDate::from_cbor(&cbor).unwrap();
        assert_eq!(decoded, date);
    }

    #[test]
    fn full_date_from_plain_text() {
        let val = Value::Text("2026-03-19".to_string());
        let date = FullDate::from_cbor(&val).unwrap();
        assert_eq!(date.as_str(), "2026-03-19");
    }
}
