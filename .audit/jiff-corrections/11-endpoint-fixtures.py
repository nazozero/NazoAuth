from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
path = root / 'crates/server/tests/unit/http/token/authorization_code.rs'
s = path.read_text().replace('.first::<Option<Timestamp>>(&mut conn)', '.first::<Option<jiff_diesel::Timestamp>>(&mut conn)')
s = s.replace('.expect("refresh token row should load")', '.expect("refresh token row should load").map(Into::into)')
path.write_text(s)
path = root / 'crates/server/tests/unit/keyctl/openid4vc_material.rs'
s = re.sub(r'\.revocation_date\s*\.as_second\(\)', '.revocation_date.timestamp()', path.read_text())
path.write_text(s)
path = root / 'crates/server/tests/unit/http/framework_boundary_transport/authorization_contract.rs'
s = path.read_text().replace('        expires - issued,', '        expires.duration_since(issued),')
path.write_text(s)

# Current-source comments must not describe the removed library's wall clock.
for name in ('crates/server/tests/unit/adapters/audit/recovery.rs', 'crates/server/tests/unit/mdoc_http_performance.rs'):
    path = root / name
    s = path.read_text().replace('does not advance Utc', 'does not advance the Jiff wall clock').replace('live Utc clock', 'live Jiff wall clock')
    path.write_text(s)
