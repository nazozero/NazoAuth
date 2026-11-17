from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1])
paths = [root / p for p in subprocess.check_output(['git', '-C', str(root), 'ls-files', '*.rs'], text=True).splitlines()]


def edit(name, transform):
    path = root / name
    before = path.read_text()
    after = transform(before)
    if before != after:
        path.write_text(after)


# These constructor names are specific to the removed Chrono API; std::time
# uses from_secs/from_millis and is deliberately not rewritten.
for path in paths:
    text = before = path.read_text()
    for old, new in [('seconds', 'from_secs'), ('minutes', 'from_mins'), ('hours', 'from_hours'), ('milliseconds', 'from_millis'), ('microseconds', 'from_micros'), ('nanoseconds', 'from_nanos')]:
        text = re.sub(r'(?<![\w:])Duration::' + old + r'\(', 'jiff::SignedDuration::' + new + '(', text)
    text = re.sub(r'(?<![\w:])Duration::days\(([^()]*)\)', r'jiff::SignedDuration::from_hours((\1) * 24)', text)
    # Fixed elapsed durations, not calendar spans.
    text = re.sub(r'\(([\w.]+) - ((?:jiff::)?Timestamp::now\(\)|[\w.]+)\)\s*\.(?:as_secs|num_seconds)\(\)', r'\1.duration_since(\2).as_secs()', text)
    text = re.sub(r'((?:jiff::)?Timestamp::new\([^\n;]*?,\s*0\))\.ok_or_else\(\|\|', r'\1.map_err(|_|', text)
    if 'persistence-postgres' in str(path):
        text = text.replace('.eq::<Option<Timestamp>>(None)', '.eq::<Option<jiff_diesel::Timestamp>>(None)')
    if before != text:
        path.write_text(text)

edit('crates/authorization-server/src/token/ciba/poll.rs', lambda s: s.replace('let Some(grant_expires_at) = jiff::Timestamp::new(ciba.expires_at, 0)', 'let Ok(grant_expires_at) = jiff::Timestamp::from_second(ciba.expires_at)'))
edit('crates/authorization-server/src/token/issue/authorization_code_state.rs', lambda s: s.replace('Timestamp::new(access_token_expires_at, 0),', 'Timestamp::from_second(access_token_expires_at).ok(),'))
edit('crates/authorization-server/src/domain/openid4vc/crypto_helpers.rs', lambda s: s.replace('jiff::Timestamp::new(value.get(name)?.as_i64()?, 0)', 'jiff::Timestamp::from_second(value.get(name)?.as_i64()?).ok()'))

# Corrupt state must not acquire a plausible new creation/expiry time.
edit('crates/authorization-server/src/token/ciba/decision.rs', lambda s: re.sub(
    r'Timestamp::new\(payload\.(issued_at|expires_at), 0\)\.unwrap_or_else\(Timestamp::now\)',
    lambda m: 'Timestamp::from_second(payload.' + m[1] + ').map_err(|_| OAuthEndpointError::json(StatusCode::SERVICE_UNAVAILABLE, "server_error", "CIBA request state is invalid."))?', s))

# One fallible boundary conversion; no saturating TTL or fallback wall clock.
edit('crates/authorization-server/src/domain/mfa_profile.rs', lambda s: re.sub(
    r'let now = Timestamp::new\(command.context.now, 0\)\.unwrap_or_else\(Timestamp::now\);\s*let ttl = i64::try_from\(self.remembered_mfa_ttl_seconds\)\.unwrap_or\(i64::MAX\);',
    'let expires_at = Timestamp::from_second(command.context.now)\n'
    '                    .and_then(|now| now.checked_add(std::time::Duration::from_secs(self.remembered_mfa_ttl_seconds)))\n'
    '                    .map_err(|_| MfaProfileError::new(MfaProfileErrorKind::RememberDeviceFailed))?;',
    s).replace('now + SignedDuration::from_secs(ttl),', 'expires_at,'))

revocation = root / 'crates/persistence-postgres/src/repositories/access_token_revocation.rs'
s = revocation.read_text()
s = s.replace('pub revoked_at: Timestamp,', 'pub revoked_at: jiff_diesel::Timestamp,').replace('pub expires_at: Timestamp,', 'pub expires_at: jiff_diesel::Timestamp,')
s = s.replace('.ok_or_else(|| {', '.map_err(|_| {')
s = re.sub(r'access_token_revocations::expires_at.eq\(\(diesel::dsl::sql::<.*?\.to_diesel\(\)\)', '''access_token_revocations::expires_at.eq(diesel::dsl::sql::<diesel::sql_types::Timestamptz>(
                "GREATEST(access_token_revocations.expires_at, EXCLUDED.expires_at)",
            ))''', s, count=1, flags=re.S)
s = s.replace('.lt((excluded(access_token_revocations::expires_at)).to_diesel())', '.lt(excluded(access_token_revocations::expires_at))')
s = s.replace('\nuse jiff_diesel::ToDiesel as _;\n', '\n')
revocation.write_text(s)

edit('crates/persistence-postgres/src/repositories/audit.rs', lambda s: s.replace(
    'deliveries.iter().map(|value| value.expires_at).collect()',
    'deliveries.iter().map(|value| value.expires_at.to_diesel()).collect()'
).replace('(&expires_at).to_diesel()', '&expires_at')
 .replace('next_attempt_at.eq(next_attempt_at)', 'next_attempt_at.eq(next_attempt_at.to_diesel())')
 .replace('Timestamp::from(event.occurred_at)', 'Timestamp::try_from(event.occurred_at).map_err(|error| RepositoryError::Consistency(format!("audit timestamp is out of range: {error}")))?'))

edit('crates/persistence-postgres/src/repositories/audit_ledger.rs', lambda s: s.replace(
    'let occurred_ats: Vec<Timestamp> = events.iter().map(|event| event.occurred_at).collect();',
    'let occurred_ats: Vec<_> = events.iter().map(|event| event.occurred_at.to_diesel()).collect();'
).replace('(occurred_ats).to_diesel()', 'occurred_ats'))

edit('crates/persistence-postgres/src/repositories/clients/query.rs', lambda s: s.replace(
    '.load::<(String, String, Value, Timestamp, i32)>',
    '.load::<(String, String, Value, jiff_diesel::Timestamp, i32)>'
).replace('                        last_authorized_at,\n                        authorization_count,',
          '                        last_authorized_at: last_authorized_at.into(),\n                        authorization_count,'))

for name in ('desired', 'instance'):
    edit('crates/persistence-postgres/src/repositories/runtime_modules/' + name + '.rs', lambda s: s.replace(
        'Timestamp::from(change.next.updated_at)',
        'Timestamp::try_from(change.next.updated_at).map_err(|error| RuntimeTransactionError::Repository(RepositoryError::Consistency(format!("runtime update timestamp is out of range: {error}"))))?'
    ).replace('change.next.drain_deadline.map(Timestamp::from)',
        'change.next.drain_deadline.map(Timestamp::try_from).transpose().map_err(|error| RuntimeTransactionError::Repository(RepositoryError::Consistency(format!("runtime drain deadline is out of range: {error}"))))?'))

print('Applied fixed-duration, fail-closed deadline and SQL-boundary corrections.')
