from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
path = root / 'crates/key-management/src/mtls_trust.rs'
text = path.read_text().replace(
    '.and_then(|value| value.strip_suffix(END_CERTIFICATE))\n        .map_err(|_| MtlsTrustAnchorError::InvalidPem)?',
    '.and_then(|value| value.strip_suffix(END_CERTIFICATE))\n        .ok_or(MtlsTrustAnchorError::InvalidPem)?')
path.write_text(text)
paths = [root / p for p in subprocess.check_output(['git', '-C', str(root), 'ls-files', '*.rs'], text=True).splitlines()]
for path in paths:
    text = old = path.read_text()
    text = text.replace('Utc::now', 'jiff::Timestamp::now')
    text = text.replace('DateTime::<Utc>::from(UNIX_EPOCH)', 'jiff::Timestamp::UNIX_EPOCH')
    if text != old:
        path.write_text(text)
for name in (
    'crates/authorization-server/src/domain/passkey.rs',
    'crates/authorization-server/tests/unit/domain/openid4vc/credential_proofs.rs',
    'crates/persistence-postgres/src/convert/identity.rs',
    'crates/persistence-postgres/tests/unit/repositories/tokens.rs',
):
    path = root / name
    path.write_text(path.read_text().replace('.timestamp()', '.as_second()'))
path = root / 'crates/nazoauth/src/endpoints/profile/avatar.rs'
path.write_text(path.read_text().replace('start.expires_at.to_rfc3339()', 'start.expires_at.to_string()'))
