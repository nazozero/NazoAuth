# 0.3.0 release preflight and review follow-up

The release preparation follows merged PR #242 and model/storage PR #238.

## Protocol package dependency

`cargo +1.99.0 package --locked --package nazo-operator-protocol` failed with
exit 1 at the original source because `nazo-crypto` is not in crates.io.
Packaging both workspace crates together succeeds and verifies both extracted
packages. Publication now attests both crates and enforces exactly ten assets
(eight server binaries and two crates). No `--no-verify` bypass is used.

## PR #242 review: live receipt cutover

[Review thread](https://github.com/nazozero/NazoAuth/pull/242#discussion_r4237984018)
identified a real missing migration guard. Released ordinary receipts have null
ciphertext but retain a replay/revocation window; they do not carry a verified
refresh-family identity. Ciphertext absence therefore cannot admit migration.
The corrected migration rejects every legacy row whose original `expires_at`
has not passed, transactionally preserving its data. It does not guess family
identity, revoke unrelated users, delete rows, or shorten security TTLs.

The new real PostgreSQL regression was run first against the migration at
`dd2ab8283164fc8bd85f66742ecd9ebbfddbd8c1` and failed after successful compilation:
`live plaintext receipts must prevent cutover: ()` (Cargo exit 101). The fixed
migration passes the same test (exit 0; one test passed, none ignored). It covers
encrypted and plaintext live receipts, failed-transaction rollback, expired
receipt conversion, original ownership/digests/retention, cleanup owner/grants,
already-compact no-op and interrupted-upgrade resumption.

Command, for each source, using only the isolated PostgreSQL fixture:

```sh
cargo +1.99.0 test --release --locked -p nazo-postgres   --test released_issuance_cutover -- --nocapture
cargo +1.99.0 fmt --all
python3 scripts/verify_static_contracts.py
git diff --check
```

`NAZO_AUDIT_TEST_DATABASE_URL` is supplied privately. The fixture deadline
changes model expired rows only; they are not production upgrade instructions.
The migration checksum update is explicit and limited to this reviewed file.
One local edit script had a syntax error before making changes; the immediate
rerun still failed on the unchanged migration and is not positive evidence.

## Upgrade limit

A stopped v0.2.16 issuer may need to wait for the original refresh-token lifetime,
not just an authorization-code window. An already-applied cutover does not replay
this guard; assessing it requires the original pre-upgrade snapshot. See the
[upgrade guide](../operations/upgrade-from-v0.2.16.md). This release preparation
does not redeploy production or retroactively invent absent family links.

The other PR #242 inline finding (CodeQL alert 590) is the previously documented
cross-field false positive, already resolved with retained SARIF evidence. New
release PR reviews contain no additional findings at this review point. Exact
final-main CI and signed release jobs remain separate publication gates.
