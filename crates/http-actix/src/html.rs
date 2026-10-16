use std::fmt::{self, Write};

pub(crate) struct HtmlAttribute<'a>(pub &'a str);

impl fmt::Display for HtmlAttribute<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in self.0.chars() {
            match ch {
                '&' => output.write_str("&amp;"),
                '"' => output.write_str("&quot;"),
                '\'' => output.write_str("&#39;"),
                '<' => output.write_str("&lt;"),
                '>' => output.write_str("&gt;"),
                _ => output.write_char(ch),
            }?;
        }
        Ok(())
    }
}

/// Contents of a single-quoted JavaScript string embedded in HTML.
pub(crate) struct JsString<'a>(pub &'a str);

impl fmt::Display for JsString<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in self.0.chars() {
            match ch {
                '\\' => output.write_str("\\\\"),
                '\r' => output.write_str("\\r"),
                '\n' => output.write_str("\\n"),
                '\'' => output.write_str("\\'"),
                '<' => output.write_str("\\u003c"),
                '>' => output.write_str("\\u003e"),
                '&' => output.write_str("\\u0026"),
                '\u{2028}' => output.write_str("\\u2028"),
                '\u{2029}' => output.write_str("\\u2029"),
                _ => output.write_char(ch),
            }?;
        }
        Ok(())
    }
}
