#!/usr/bin/env python3
"""Resolve the inspected frozen-peer merge, preserving both branches' contracts."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
peer = 'e0014c4a7088085b7b08288ae5f739f27f3f818c'
base = '294baefd71b60b96d91fd0ae4574b51221f2a06e'

def git(*args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True)

conflicts = git('diff', '--name-only', '--diff-filter=U').splitlines()
allowed = {
    'Cargo.lock': 'both',
    'crates/authorization-server/src/domain/openid4vc/credential_crypto/mdoc.rs': 'theirs',
    'crates/authorization-server/tests/unit/domain/openid4vc_credential_crypto.rs': 'theirs',
    'crates/key-management/src/model.rs': 'ours',
}
unknown = set(conflicts) - set(allowed)
if unknown:
    raise SystemExit('Unreviewed merge conflicts: ' + repr(unknown))
for name in conflicts:
    path = root / name
    text = path.read_text()
    mode = allowed[name]
    def resolve(match):
        return match[1] if mode == 'ours' else match[2] if mode == 'theirs' else match[1] + match[2]
    text, count = re.subn(r'^<<<<<<<[^\n]*\n(.*?)^=======\n(.*?)^>>>>>>>[^\n]*\n', resolve, text, flags=re.M | re.S)
    if not count or re.search(r'^(<<<<<<<|=======|>>>>>>>)', text, re.M):
        raise SystemExit('Unexpected conflict framing: ' + name)
    path.write_text(text)

# Only migrate peer-touched files. Existing Jiff fixes are retained by git's
# three-way merge; no peer security logic or test is reverted wholesale.
changed = git('diff', '--name-only', base, peer).splitlines()
for name in changed:
    path = root / name
    if path.suffix != '.rs':
        continue
    text = path.read_text()
    def items(m):
        output = []
        for item in m[1].split(','):
            item = item.strip()
            if item in ('Utc', 'DateTime'):
                item = 'Timestamp'
            elif item in ('TimeZone', 'TimeZone as _', 'SecondsFormat'):
                continue
            elif item == 'Duration':
                item = 'SignedDuration'
            if item and item not in output:
                output.append(item)
        return 'use jiff::{' + ', '.join(output) + '};' if output else ''
    text = re.sub(r'use chrono::\{([^}]+)\};', items, text)
    text = text.replace('use chrono::Utc;', 'use jiff::Timestamp;')
    text = re.sub(r'(?<!\w)(?:chrono::)?DateTime(?:::)?\s*<\s*(?:chrono::)?Utc\s*>', 'jiff::Timestamp', text)
    text = text.replace('chrono::Utc::now', 'jiff::Timestamp::now')
    text = text.replace('Utc::now', 'jiff::Timestamp::now')
    text = text.replace('chrono::Duration', 'jiff::SignedDuration')
    text = text.replace('ChronoDuration::', 'jiff::SignedDuration::')
    for before, after in [('seconds','from_secs'), ('minutes','from_mins'), ('hours','from_hours'), ('milliseconds','from_millis'), ('microseconds','from_micros'), ('nanoseconds','from_nanos')]:
        text = re.sub(r'(?<![\w:])Duration::' + before + r'\(', 'jiff::SignedDuration::' + after + '(', text)
        text = text.replace('SignedDuration::' + before + '(', 'SignedDuration::' + after + '(')
    text = re.sub(r'(?<![\w:])Duration::days\(([^()]*)\)', r'jiff::SignedDuration::from_hours((\1) * 24)', text)
    text = re.sub(r'SignedDuration::days\(([^()]*)\)', r'SignedDuration::from_hours((\1) * 24)', text)
    text = text.replace('.num_seconds()', '.as_secs()')
    text = text.replace('.signed_duration_since(', '.duration_since(')
    # DateTime parsing/formatting changes are left for explicit diagnostics,
    # not guessed across ASN.1, mdoc and the time crate.
    text = re.sub(r'([\w.]+)\.timestamp\(\)', lambda m: m[0] if m[1].endswith(('.not_before','.not_after','.revocation_date')) else m[1]+'.as_second()', text)
    text = re.sub(r'(\.revocation_date\s*)\.as_second\(\)', r'\1.timestamp()', text)
    # A protocol Timestamp is not the domain timestamp imported from Jiff.
    if name.endswith('/credential_crypto/mdoc.rs'):
        text = re.sub(r'(?<![\w:])Timestamp::from_unix_', 'MdocTimestamp::from_unix_', text)
    path.write_text(text)

# Record the precise reconciliation; compilation/tests are deliberately pending.
record = root / '.verification/jiff-peer-merge.md'
record.write_text(
    '# Jiff peer reconciliation\n\n'
    'Peer: `' + peer + '`. Merge base: `' + base + '`.\n\n'
    'The inspected conflicts retain the current DS/IACA profile, issuer binding, '
    'mDL issuer attributes and shared verification instant from the peer. '
    'Jiff-to-protocol fallible conversion, POSIX leap-second rejection and frozen '
    'audit encodings remain. Peer-added code is converted to domain Jiff types; '
    'protocol and ASN.1 clocks remain distinct.\n\n'
    'Compilation and execution of this merged tree are pending. Earlier validation '
    'records describe their named source trees only.\n'
)
subprocess.run(['git', '-C', str(root), 'add', '--', *conflicts, *[p for p in changed if p.endswith('.rs')], str(record)], check=True)
print('Resolved inspected conflicts and staged peer-owned security changes with Jiff adapters.')
