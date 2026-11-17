from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1])
paths = [root / p for p in subprocess.check_output(['git', '-C', str(root), 'ls-files', '*.rs'], text=True).splitlines()]
for path in paths:
    value = old = path.read_text()
    value = value.replace('OffsetTimestamp', 'OffsetDateTime')
    value = value.replace('Utc::now().timestamp()', 'jiff::Timestamp::now().as_second()')
    value = value.replace('Utc::now()', 'jiff::Timestamp::now()')
    value = value.replace('SignedDuration::zero()', 'SignedDuration::ZERO')
    value = re.sub(r'\bTimeZone as _,\s*', '', value)
    value = re.sub(r'\bTimeZone as _\s*,?', '', value)
    # Explicit precision keeps existing seconds/milliseconds + Z wire formats.
    # Receivers here are a single path or a parenthesized expression.
    value = re.sub(
        r'(\([^\n;]+\)|\b[\w.]+)\s*\.to_rfc3339_opts\((?:chrono::)?SecondsFormat::(Secs|Millis),\s*true\)',
        lambda m: 'format!("{:.%s}", %s)' % ('0' if m[2] == 'Secs' else '3', m[1]), value)
    # Deterministic UTC test fixtures do not need a time-zone database.
    value = re.sub(
        r'Utc\s*\.with_ymd_and_hms\((\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)\s*\.single\(\)',
        lambda m: '"%04d-%02d-%02dT%02d:%02d:%02dZ".parse::<jiff::Timestamp>()' % tuple(map(int, m.groups())), value)
    if str(path).endswith('crates/key-management/src/mtls_trust.rs'):
        value = value.replace('.ok_or(MtlsTrustAnchorError::InvalidPem)', '.map_err(|_| MtlsTrustAnchorError::InvalidPem)')
    if str(path).endswith('crates/state-store-valkey/src/avatar_upload_state.rs'):
        value = value.replace('.ok_or_else(|| Error::corrupt_data("invalid avatar upload expiry"))', '.map_err(|_| Error::corrupt_data("invalid avatar upload expiry"))')
    if str(path).endswith('crates/key-management/tests/unit/database.rs'):
        for variable in ('loaded_snapshot', 'reloaded_snapshot'):
            value = value.replace(variable + '.next_update - ' + variable + '.this_update', variable + '.next_update.duration_since(' + variable + '.this_update)')
    if value != old:
        path.write_text(value)
