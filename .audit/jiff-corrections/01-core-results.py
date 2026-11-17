from pathlib import Path
import sys
root = Path(sys.argv[1])
changes = {
    'crates/authorization-server-core/src/token_service.rs': (
        'expires_at: Timestamp::new(claims.exp, 0)?,',
        'expires_at: Timestamp::from_second(claims.exp).ok()?,',
    ),
    'crates/authorization-server-core/src/extension_grants.rs': (
        'jiff::Timestamp::new(claims.exp, 0).ok_or(JwtBearerGrantError::InvalidAssertion)?',
        'jiff::Timestamp::from_second(claims.exp).map_err(|_| JwtBearerGrantError::InvalidAssertion)?',
    ),
}
for name, (old, new) in changes.items():
    path = root / name
    value = path.read_text()
    if old in value:
        path.write_text(value.replace(old, new))
