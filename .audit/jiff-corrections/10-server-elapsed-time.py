from pathlib import Path
import re
import sys

root = Path(sys.argv[1])


def edit(name, operation):
    path = root / name
    text = path.read_text()
    changed = operation(text)
    if changed != text:
        path.write_text(changed)


edit('crates/persistence-postgres/tests/controller_recovery.rs', lambda s: s.replace(
    '(issued.expires_at - at(4)).as_secs()', 'issued.expires_at.duration_since(at(4)).as_secs()'))
edit('crates/server/tests/unit/http/token/authorization_code.rs', lambda s: s.replace(
    'use jiff::{SignedDuration, Timestamp};', 'use jiff::SignedDuration;'))
edit('crates/server/src/operator_task/execution.rs', lambda s: s.replace(
    'outcome.not_before.timestamp()', 'outcome.not_before.as_second()'))
edit('crates/server/src/adapters/audit_anchor/worker.rs', lambda s: s.replace(
    '(now - observed).to_std()', 'Duration::try_from(now.duration_since(observed))'
).replace('(Timestamp::now() - delivery.occurred_at).as_secs()',
          'Timestamp::now().duration_since(delivery.occurred_at).as_secs()'))
edit('crates/server/src/settings/config_loader.rs', lambda s: s.replace('.num_seconds()', '.as_secs()'))
edit('crates/server/tests/unit/adapters/audit_anchor/worker.rs', lambda s: s.replace(
    'ChronoDuration::milliseconds(', 'jiff::SignedDuration::from_millis('
).replace('ChronoDuration::seconds(', 'jiff::SignedDuration::from_secs('))
edit('crates/persistence-postgres/tests/scim_security_events.rs', lambda s: s.replace(
    'jiff::SignedDuration::from_mins(occurred_minutes_ago),).to_diesel()',
    'jiff::SignedDuration::from_mins(occurred_minutes_ago)).to_diesel()'
).replace('jiff::SignedDuration::from_mins(expires_minutes_from_now),).to_diesel()',
          'jiff::SignedDuration::from_mins(expires_minutes_from_now)).to_diesel()'))
edit('crates/persistence-postgres/tests/token_issuance_fresh.rs', lambda s: s.replace(
    'jiff::Timestamp::new(current.access_token_expires_at, 0),',
    'jiff::Timestamp::from_second(current.access_token_expires_at).ok(),'))
