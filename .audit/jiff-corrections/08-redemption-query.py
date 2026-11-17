from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
path = root / 'crates/persistence-postgres/src/repositories/token_issuance.rs'
text = path.read_text()
text = text.replace(
    '.first::<(String, Timestamp, Option<Uuid>, Option<serde_json::Value>)>',
    '.first::<(String, jiff_diesel::Timestamp, Option<Uuid>, Option<serde_json::Value>)>',
)
text = text.replace(
    '                        access_token_jti,\n                        access_token_expires_at,\n                        refresh_token_family_id,',
    '                        access_token_jti,\n                        access_token_expires_at: access_token_expires_at.into(),\n                        refresh_token_family_id,',
)
path.write_text(text)

# Preserve the same old timestamp encoding for optional fields as for required
# fields, even when rustfmt breaks the receiver across several lines.
path = root / 'crates/nazoauth/src/http/runtime_modules.rs'
text = re.sub(
    r'\.map\(timestamp\)\s*\.transpose\(\)\s*\.map_err\(<S::Error as serde::ser::Error>::custom\)\?',
    '.map(RuntimeTimestamp)', path.read_text(),
)
path.write_text(text)
