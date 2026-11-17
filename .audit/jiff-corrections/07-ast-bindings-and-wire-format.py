from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1])


def edit(name, transform):
    path = root / name
    before = path.read_text()
    after = transform(before)
    if after != before:
        path.write_text(after)


for path in (root / 'crates/persistence-postgres').rglob('*.rs'):
    text = old = path.read_text()
    # SQL expressions are already typed. They are not host timestamps.
    text = re.sub(r'\((diesel::dsl::sql::<[^()]*>\(\s*"[^"]*"\s*,?\s*\))\)\s*\.to_diesel\(\)', r'\1', text)
    if text != old:
        path.write_text(text)

edit('crates/persistence-postgres/src/repositories/scim.rs', lambda s: s.replace(
    '.get_result::<jiff::Timestamp>(connection)', '.get_result::<jiff_diesel::Timestamp>(connection)'
).replace('                                deactivated_at,', '                                deactivated_at.into(),'))

edit('crates/persistence-postgres/src/repositories/token_issuance.rs', lambda s: re.sub(
    r'(\.checked_add\(jiff::SignedDuration::from_secs\(\s*MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,\s*\)\)\s*)\.ok_or\(TokenPortError::CorruptData\)',
    r'\1.map_err(|_| TokenPortError::CorruptData)', s))

# AstPass holds references for the lifetime of the query. Store its tiny,
# transparent SQL scalar wrappers on the existing query object: no new heap
# allocations, input cloning, dynamic SQL or loss of prepared-statement identity.
def audit_query(s):
    s = s.replace("struct AuditAppendQuery<'a> {\n    event: &'a SecurityAuditEvent,\n}",
        "struct AuditAppendQuery<'a> {\n    event: &'a SecurityAuditEvent,\n    occurred_at: jiff_diesel::Timestamp,\n}")
    def initializer(m):
        value = m[1].strip() if m[1] else 'event'
        return 'AuditAppendQuery { event: ' + value + ', occurred_at: (' + value + ').occurred_at.into() }'
    s = re.sub(r'AuditAppendQuery\s*\{\s*event(?:\s*:\s*([^,}]+))?\s*,?\s*}', initializer, s)
    return s.replace('&self.event.occurred_at)?', '&self.occurred_at)?')
edit('crates/persistence-postgres/src/repositories/audit_ledger.rs', audit_query)

for path in (root / 'crates/persistence-postgres/tests').rglob('*.rs'):
    s = path.read_text()
    if 'AuditAppendQuery {' in s:
        path.write_text(audit_query(s))

def authorization_query(s):
    if '    valid_until: jiff_diesel::Timestamp,' in s:
        return s
    s = s.replace("    input: &'a AuthorizationDecisionCommit,", "    input: &'a AuthorizationDecisionCommit,\n    valid_until: jiff_diesel::Timestamp,\n    retain_until: jiff_diesel::Timestamp,\n    occurred_at: jiff_diesel::Timestamp,")
    s = s.replace('        input,\n        scopes:', '        input,\n        valid_until: input.valid_until.into(),\n        retain_until: input.retain_until.into(),\n        occurred_at: input.occurred_at.into(),\n        scopes:')
    for field in ('valid_until', 'retain_until', 'occurred_at'):
        s = s.replace('&self.input.' + field + ')?', '&self.' + field + ')?')
    return s
edit('crates/persistence-postgres/src/repositories/authorization_flow.rs', authorization_query)

def family_query(s):
    if '    issued_at: jiff_diesel::Timestamp,' in s:
        return s
    s = s.replace("    token: &'a nazo_auth::NewRefreshToken,", "    token: &'a nazo_auth::NewRefreshToken,\n    issued_at: jiff_diesel::Timestamp,\n    expires_at: jiff_diesel::Timestamp,")
    s = s.replace('        token,\n        contract,', '        token,\n        issued_at: token.issued_at.into(),\n        expires_at: token.expires_at.into(),\n        contract,')
    for field in ('issued_at', 'expires_at'):
        s = s.replace('&self.token.' + field + ')?', '&self.' + field + ')?')
    return s
edit('crates/persistence-postgres/src/repositories/tokens/create_family.rs', family_query)

edit('crates/persistence-postgres/tests/unit/repositories/access_token_revocation.rs', lambda s: s.replace(
    '        revoked_at,\n        expires_at,', '        revoked_at: revoked_at.into(),\n        expires_at: expires_at.into(),'
).replace('foreign.expires_at, foreign_expires_at,', 'foreign.expires_at, jiff::Timestamp::from(foreign_expires_at),'))

runtime_serializer = '''
// Keep this endpoint's existing RFC3339 bytes (0/3/6/9 fractional digits and
// +00:00) while streaming the value to serde without an intermediate String.
struct RuntimeTimestamp(SystemTime);

impl Serialize for RuntimeTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = timestamp(self.0).map_err(<S::Error as serde::ser::Error>::custom)?;
        let nanos = value.subsec_nanosecond();
        let precision = if nanos == 0 {
            0
        } else if nanos % 1_000_000 == 0 {
            3
        } else if nanos % 1_000 == 0 {
            6
        } else {
            9
        };
        let civil = value.to_zoned(jiff::tz::TimeZone::UTC).datetime();
        serializer.collect_str(&format_args!("{civil:.precision$}+00:00"))
    }
}

'''
def runtime_wire(s):
    if 'struct RuntimeTimestamp(' in s:
        return s
    s = re.sub(r'&([\w.]+)\s*\.map\(timestamp\)\s*\.transpose\(\)\s*\.map_err\(<S::Error as serde::ser::Error>::custom\)\?', r'&\1.map(RuntimeTimestamp)', s)
    s = re.sub(r'&timestamp\(([\w.]+)\)\s*\.map_err\(<S::Error as serde::ser::Error>::custom\)\?', r'&RuntimeTimestamp(\1)', s)
    return s.replace('fn timestamp(value: SystemTime)', runtime_serializer + 'fn timestamp(value: SystemTime)', 1)
edit('crates/nazoauth/src/http/runtime_modules.rs', runtime_wire)
edit('crates/nazoauth/tests/unit/http/runtime_modules.rs', lambda s: re.sub(
    r'timestamp\((UNIX_EPOCH [+-] std::time::Duration::from_millis\(1500\))\)',
    r'serde_json::to_value(RuntimeTimestamp(\1)).unwrap()', s))

runtime_tests = '''
#[test]
fn runtime_timestamp_wire_preserves_precision_and_rejects_unrepresentable_instants() {
    for (nanos, expected) in [
        (0_i64, "1970-01-01T00:00:00+00:00"),
        (1, "1970-01-01T00:00:00.000000001+00:00"),
        (1_000, "1970-01-01T00:00:00.000001+00:00"),
        (1_000_000, "1970-01-01T00:00:00.001+00:00"),
        (-1, "1969-12-31T23:59:59.999999999+00:00"),
    ] {
        let duration = std::time::Duration::from_nanos(nanos.unsigned_abs());
        let value = if nanos < 0 { UNIX_EPOCH - duration } else { UNIX_EPOCH + duration };
        assert_eq!(serde_json::to_value(RuntimeTimestamp(value)).unwrap(), expected);
    }
    let outside = UNIX_EPOCH + std::time::Duration::from_secs(253_402_300_800);
    assert!(serde_json::to_value(RuntimeTimestamp(outside)).is_err());
}
'''
edit('crates/nazoauth/tests/unit/http/runtime_modules.rs', lambda s: s if 'fn runtime_timestamp_wire_preserves_precision_and_rejects_unrepresentable_instants' in s else s + runtime_tests)
print('Applied borrowed-query lifetime and byte-preserving timestamp serialization fixes.')
