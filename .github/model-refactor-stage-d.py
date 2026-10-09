from pathlib import Path
p = Path('crates/authorization-server/tests/unit/authorization/request/parameters.rs')
s = p.read_text()
assert 'use nazo_auth::OidcClaimRequest;' not in s
p.write_text('use nazo_auth::OidcClaimRequest;\n' + s)
p = Path('crates/authorization-server/src/token/issue_grant.rs')
s = p.read_text()
old = '        let sector_identifier_host = client.sector_identifier_host.as_deref();\n'
assert s.count(old) == 1
p.write_text(s.replace(old, ''))
