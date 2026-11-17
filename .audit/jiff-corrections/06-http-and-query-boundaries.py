from pathlib import Path
import json
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


# The compiler identifies these as Diesel's SQL CURRENT_TIMESTAMP expression,
# not an application Timestamp. Only replace the exact diagnosed source lines.
diagnostics = root / '.verification/jiff-check.json'
if diagnostics.exists():
    for error in json.loads(diagnostics.read_text()).get('errors', []):
        if 'no method named `to_diesel` found for struct `now`' not in error['message']:
            continue
        for site in error.get('sites', []):
            path = root / site['file']
            if not path.is_file():
                continue
            text = path.read_text()
            for line in site.get('text', []):
                before = line['text']
                after = before.replace('(now).to_diesel()', 'now')
                text = text.replace(before, after)
            path.write_text(text)

paths = [root / p for p in subprocess.check_output(['git', '-C', str(root), 'ls-files', '*.rs'], text=True).splitlines()]
for path in paths:
    text = before = path.read_text()
    if 'persistence-postgres' in str(path):
        # SQL-only Insertable owns official transparent adapter values, retaining
        # borrowed batch insertion and avoiding a conversion Vec at execute().
        def record(match):
            body = match[1]
            def field(field_match):
                expression = field_match[2].strip()
                if expression.endswith('.into()'):
                    return field_match[0]
                return field_match[1] + '(' + expression + ').into(),'
            body = re.sub(r'(^[ \t]*(?:revoked_at|expires_at):\s*)([^,\n]+),', field, body, flags=re.M)
            return 'NewAccessTokenRevocation {' + body + '}'
        text = re.sub(r'NewAccessTokenRevocation\s*\{([^{}]*)}', record, text)
    text = re.sub(r'(Timestamp::new\([^\n;]*\))\s*\.single\(\)', r'\1', text)
    if text != before:
        path.write_text(text)

edit('crates/persistence-postgres/src/repositories/token_issuance.rs', lambda s: s.replace(
    'row.expires_at > existing.expires_at {', 'row.expires_at > existing.expires_at.into() {'
).replace('existing.expires_at = row.expires_at;', 'existing.expires_at = row.expires_at.into();'))

edit('crates/persistence-postgres/src/repositories/security_state.rs', lambda s: s.replace(
    '(after.map(|row| row.created_at),).to_diesel()', 'after.map(|row| row.created_at).to_diesel()'))

edit('crates/persistence-postgres/src/repositories/tokens.rs', lambda s: s.replace(
    '.first::<(String, Uuid, Uuid, Timestamp, i64, i16)>', '.first::<(String, Uuid, Uuid, jiff_diesel::Timestamp, i64, i16)>'
).replace('not_before: stored_not_before,', 'not_before: stored_not_before.into(),')
 .replace('.first::<(Uuid, Timestamp)>', '.first::<(Uuid, jiff_diesel::Timestamp)>')
 .replace('retry.retry_started_at.duration_since(spent_at)', 'retry.retry_started_at.duration_since(spent_at.into())'))

edit('crates/nazoauth/src/endpoints/admin/access_requests.rs', lambda s: re.sub(
    r'let Some\(expires_at\) = i64::try_from\(config.delivery_ttl_seconds\)\s*\.ok\(\)\s*\.and_then\(SignedDuration::try_seconds\)\s*\.and_then\(\|ttl\| Timestamp::now\(\).checked_add\(ttl\)\)',
    'let Ok(expires_at) = Timestamp::now().checked_add(std::time::Duration::from_secs(config.delivery_ttl_seconds))', s))

edit('crates/nazoauth/src/control/controller_registry.rs', lambda s: re.sub(
    r'let remaining = ([\w.]+) - ([\w.]+);', r'let remaining = \1.duration_since(\2);', s))

# The response serializer already has an error path. Convert once there and
# let Jiff serialize directly rather than allocate an intermediate RFC3339 String.
# Compute epoch nanoseconds explicitly so web_time and native SystemTime agree.
def runtime_wire(s):
    old = '''fn timestamp(value: SystemTime) -> String {
    let value = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => std::time::UNIX_EPOCH + duration,
        Err(error) => std::time::UNIX_EPOCH - error.duration(),
    };
    Timestamp::from(value).to_string()
}'''
    new = '''fn timestamp(value: SystemTime) -> Result<Timestamp, jiff::Error> {
    let nanos = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    };
    Timestamp::from_nanosecond(nanos)
}'''
    if old not in s:
        return s
    s = s.replace(old, new)
    s = re.sub(r'&([\w.]+)\.map\(timestamp\)', r'&\1.map(timestamp).transpose().map_err(<S::Error as serde::ser::Error>::custom)?', s)
    s = re.sub(r'&timestamp\(([\w.]+)\)', r'&timestamp(\1).map_err(<S::Error as serde::ser::Error>::custom)?', s)
    return s
edit('crates/nazoauth/src/http/runtime_modules.rs', runtime_wire)

# A concise source index complements full compiler diagnostics, without
# changing their outcome. It helps audit remaining boundary conversions.
if diagnostics.exists():
    unique = set()
    lines = []
    for error in json.loads(diagnostics.read_text()).get('errors', []):
        for site in error.get('sites', []):
            key = (site['file'], site['line'], error['message'])
            if key not in unique:
                unique.add(key)
                lines.append(f"{site['file']}:{site['line']}: {error['message']}")
    (root / '.verification/previous-errors-index.txt').write_text('\n'.join(lines) + '\n')
print('Applied runtime serialization and typed SQL query corrections.')
