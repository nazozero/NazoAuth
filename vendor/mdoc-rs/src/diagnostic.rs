//! CBOR diagnostic-notation pretty printer (feature: `debug`).
//!
//! Renders a [`ciborium::Value`] in the Extended Diagnostic Notation of
//! RFC 8949 §8 (and RFC 8610 Appendix G), which is invaluable when debugging
//! mdoc interop failures — you can eyeball the exact structure, tags, and byte
//! strings of a `DeviceResponse` / MSO without a hex editor.
//!
//! This is a triage aid, not a canonical serializer.

use ciborium::Value;

/// Render a decoded CBOR value as a single-line diagnostic-notation string.
///
/// Examples: `{"docType": "org.iso.18013.5.1.mDL", ...}`, `1004("2019-10-20")`,
/// `24(h'a4686469...')`.
pub fn to_diagnostic(value: &Value) -> String {
    let mut out = String::new();
    render(value, &mut out);
    out
}

/// Decode CBOR bytes and render them in diagnostic notation. Returns a short
/// error marker string if the bytes are not valid CBOR.
pub fn bytes_to_diagnostic(bytes: &[u8]) -> String {
    match ciborium::from_reader::<Value, _>(bytes) {
        Ok(v) => to_diagnostic(&v),
        Err(e) => format!("<invalid CBOR: {e}>"),
    }
}

fn render(value: &Value, out: &mut String) {
    use std::fmt::Write;
    match value {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            let _ = write!(out, "{n}");
        }
        Value::Bytes(b) => {
            out.push_str("h'");
            for byte in b {
                let _ = write!(out, "{byte:02x}");
            }
            out.push('\'');
        }
        Value::Float(f) => {
            let _ = write!(out, "{f}");
        }
        Value::Text(s) => {
            // Escape the few characters that would break the rendering.
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    _ => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
        Value::Tag(tag, inner) => {
            let _ = write!(out, "{tag}(");
            render(inner, out);
            out.push(')');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(item, out);
            }
            out.push(']');
        }
        Value::Map(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render(k, out);
                out.push_str(": ");
                render(v, out);
            }
            out.push('}');
        }
        // ciborium::Value is non-exhaustive; render anything new defensively.
        other => {
            let _ = write!(out, "{other:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_scalars() {
        assert_eq!(to_diagnostic(&Value::Integer(42i32.into())), "42");
        assert_eq!(to_diagnostic(&Value::Bool(true)), "true");
        assert_eq!(to_diagnostic(&Value::Null), "null");
        assert_eq!(to_diagnostic(&Value::Text("hi".into())), "\"hi\"");
    }

    #[test]
    fn renders_bytes_as_hex() {
        assert_eq!(
            to_diagnostic(&Value::Bytes(vec![0xa4, 0x00, 0xff])),
            "h'a400ff'"
        );
    }

    #[test]
    fn renders_tag_with_content() {
        // full-date Tag 1004 wrapping a text date.
        let v = Value::Tag(1004, Box::new(Value::Text("2019-10-20".into())));
        assert_eq!(to_diagnostic(&v), "1004(\"2019-10-20\")");
    }

    #[test]
    fn renders_map_and_array() {
        let v = Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1i32.into())),
            (
                Value::Text("b".into()),
                Value::Array(vec![Value::Integer(2i32.into()), Value::Bool(false)]),
            ),
        ]);
        assert_eq!(to_diagnostic(&v), "{\"a\": 1, \"b\": [2, false]}");
    }

    #[test]
    fn bytes_to_diagnostic_round_trips() {
        let v = Value::Map(vec![(
            Value::Text("k".into()),
            Value::Tag(24, Box::new(Value::Bytes(vec![0x01, 0x02]))),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        assert_eq!(bytes_to_diagnostic(&buf), "{\"k\": 24(h'0102')}");
    }
}
